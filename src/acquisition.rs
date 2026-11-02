//! Acquisition lane (D-246, amended by D-248): Seahawk acquires,
//! neemu ingests.
//!
//! This module is the transport-agnostic core. It owns the
//! determination gate, the `decide()` rules for acquisition, the
//! per-work job plan, the quarantine layout, manifest write and
//! verification, the neemu ingest handoff packet, and the D-248
//! deletion lifecycle. A transport only ever places files into a
//! work's quarantine media dir and reports a capture method per
//! file; every policy decision sits here, so no transport can
//! widen the lane.
//!
//! Lane law (D-246): CLEARED-determination works and allowlisted
//! domains only; download-class captures only (the site's own
//! Download control, or Save-As on originals); a screenshot is a
//! strictly-last-resort capture, always labelled
//! `screenshot-derived` in the manifest and never counted as
//! original media. Lifecycle law (D-248): raw media is deleted
//! only after extraction is complete AND verified against the
//! manifest; the manifest, hashes, provenance, and extracted
//! outputs are retained; incomplete, failed, unverified, or held
//! media is never auto-deleted.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Typed refusal codes for the acquisition lane, carried in the
/// `error.code` field of the structured refusal result (the fleet
/// mold, as in `policy::codes`).
pub mod codes {
    pub const DISABLED: &str = "seahawk_acquisition_disabled";
    pub const NOT_CLEARED: &str = "seahawk_acquisition_not_cleared";
    pub const NO_RECORD: &str = "seahawk_acquisition_no_record";
    pub const DOMAIN_REFUSED: &str = "seahawk_acquisition_domain_refused";
    pub const UNATTENDED_BLOCKED: &str = "seahawk_acquisition_unattended_blocked";
    pub const TRANSPORT_BLOCKED: &str = "seahawk_acquisition_transport_blocked";
    pub const FILE_TOO_LARGE: &str = "seahawk_acquisition_file_too_large";
    pub const WORK_TOO_LARGE: &str = "seahawk_acquisition_work_too_large";
    pub const TOO_MANY_FILES: &str = "seahawk_acquisition_too_many_files";
    pub const TYPE_REFUSED: &str = "seahawk_acquisition_type_refused";
    pub const NO_MEDIA: &str = "seahawk_acquisition_no_media";
    pub const HASH_MISMATCH: &str = "seahawk_acquisition_hash_mismatch";
    pub const MANIFEST_INVALID: &str = "seahawk_acquisition_manifest_invalid";
    pub const SCREENSHOT_MISLABELLED: &str = "seahawk_acquisition_screenshot_mislabelled";
    pub const DELETION_REFUSED: &str = "seahawk_acquisition_deletion_refused";
    pub const BAD_RECORD: &str = "seahawk_acquisition_bad_record";
}

/// Per-file size ceiling. Raised for the game-acquisition
/// pilot (D-478 follow-on): single-file game archives of
/// 8–16 GiB are routine in this class; 16 GiB covers them
/// with headroom while staying a real ceiling.
pub const MAX_FILE_BYTES: u64 = 17_179_869_184; // 16 GiB
/// Per-work total ceiling across all captured files. A
/// base+DLC game work's captured total can reach tens of
/// GiB; 64 GiB bounds one work while four pilot works at
/// the cap (256 GiB) fit primo's free space comfortably.
pub const MAX_WORK_BYTES: u64 = 68_719_476_736; // 64 GiB
/// Per-work file-count ceiling (the worked example holds 116).
pub const MAX_FILES_PER_WORK: usize = 4_096;
/// Domain allowlist, initial entry (D-246). Policy data at
/// landing may extend this list; code never does.
pub const ALLOWED_DOMAINS: [&str; 2] = ["doujins.com", "new.lewd.ninja"];
/// S5 frozen-benchmark status. The S5 gate FAILED as frozen
/// (GATE-REPORT-S5: G1 7/11 = 63.6% against a >=90% bar; the bar
/// does not move). While this is false, unattended acquisition
/// and the Seahawk GUI transport refuse. Flipping it requires a
/// green frozen re-run on record, cited in `S5_GATE_EVIDENCE`.
pub const S5_BENCHMARK_GREEN: bool = false;
/// Evidence string naming the S5 gate state, carried in refusals.
pub const S5_GATE_EVIDENCE: &str = "S5 frozen benchmark FAILED (GATE-REPORT-S5: G1 7/11 = 63.6% \
     vs >=90% bar, G2 63.6% vs >=98%, A1 4/7 vs 100%, T1 0/2; R1 refusals 5/5); no green \
     frozen re-run is on record";

/// A typed acquisition refusal: a stable code plus a bounded,
/// human-readable message.
#[derive(Debug, Eq, PartialEq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

impl Refusal {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }
}

/// The adult-coding determination of record for a work, from the
/// corpus determination pass (fail-closed: anything that is not
/// an explicit CLEARED is not acquirable).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Determination {
    Cleared,
    Undetermined,
    Excluded,
    NoRecord,
}

impl Determination {
    fn parse(raw: &str) -> Self {
        match raw {
            "CLEARED" => Self::Cleared,
            "UNDETERMINED" => Self::Undetermined,
            "EXCLUDE" | "EXCLUDED" => Self::Excluded,
            _ => Self::NoRecord,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Cleared => "CLEARED",
            Self::Undetermined => "UNDETERMINED",
            Self::Excluded => "EXCLUDE",
            Self::NoRecord => "NO_RECORD",
        }
    }
}

/// How one file was captured. A screenshot is never an original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureMethod {
    /// The site's own Download control (a whole-work archive).
    Download,
    /// Right-click Save-As on an original media file.
    SaveAsOriginal,
    /// Screenshot, strictly last resort (D-246).
    ScreenshotDerived,
}

impl CaptureMethod {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "download" => Some(Self::Download),
            "save_as_original" => Some(Self::SaveAsOriginal),
            "screenshot_derived" => Some(Self::ScreenshotDerived),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::SaveAsOriginal => "save_as_original",
            Self::ScreenshotDerived => "screenshot_derived",
        }
    }

    pub fn is_original(&self) -> bool {
        !matches!(self, Self::ScreenshotDerived)
    }
}

/// The transport that will place files into quarantine. The core
/// is transport-agnostic; transports differ only in gating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Supervised live-browser harness (the pilot transport).
    BrowserHarness,
    /// Seahawk's own GUI tools — gated on the S5 benchmark.
    SeahawkGui,
}

impl Transport {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "browser_harness" => Some(Self::BrowserHarness),
            "seahawk_gui" => Some(Self::SeahawkGui),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BrowserHarness => "browser_harness",
            Self::SeahawkGui => "seahawk_gui",
        }
    }
}

/// Whether a human supervises the acquisition session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Supervised,
    Unattended,
}

impl Mode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "supervised" => Some(Self::Supervised),
            "unattended" => Some(Self::Unattended),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Supervised => "supervised",
            Self::Unattended => "unattended",
        }
    }
}

/// One work's acquisition record: identity, provenance, and the
/// determination of record. Built from the tool-call arguments;
/// every field is validated before use.
#[derive(Clone, Debug)]
pub struct WorkRecord {
    pub slug: String,
    pub title: String,
    pub series: String,
    pub tags: Vec<String>,
    pub source_url: String,
    pub determination: Determination,
    /// Path or identifier of the determination record of record.
    pub determination_record: String,
    pub tier_claim: String,
}

impl WorkRecord {
    /// Parses and validates a work record from tool arguments.
    /// `determination` accepts either a bare status string or an
    /// object `{status, record}`.
    pub fn from_json(args: &Value) -> Result<Self, Refusal> {
        let bad = |field: &str| {
            Refusal::new(
                codes::BAD_RECORD,
                format!("work record field {field} is missing or invalid"),
            )
        };
        let slug = args
            .get("slug")
            .and_then(Value::as_str)
            .filter(|s| valid_slug(s))
            .ok_or_else(|| bad("slug"))?
            .to_string();
        let title = args
            .get("title")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.chars().count() <= 512)
            .ok_or_else(|| bad("title"))?
            .to_string();
        let series = args
            .get("series")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tags = args
            .get("tags")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let source_url = args
            .get("source_url")
            .and_then(Value::as_str)
            .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
            .ok_or_else(|| bad("source_url"))?
            .to_string();
        let (determination, determination_record) = match args.get("determination") {
            Some(Value::String(status)) => (Determination::parse(status), String::new()),
            Some(obj @ Value::Object(_)) => (
                Determination::parse(obj.get("status").and_then(Value::as_str).unwrap_or("")),
                obj.get("record")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            ),
            _ => (Determination::NoRecord, String::new()),
        };
        let tier_claim = args
            .get("tier_claim")
            .and_then(Value::as_str)
            .unwrap_or("A")
            .to_string();
        Ok(Self {
            slug,
            title,
            series,
            tags,
            source_url,
            determination,
            determination_record,
            tier_claim,
        })
    }
}

/// Slugs name quarantine directories: lowercase kebab only, so a
/// slug can never traverse out of the quarantine root.
fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 128
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

/// The host of a URL, lowercased, without port. `None` when the
/// URL has no `scheme://host` prefix.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let hostport = rest.split(['/', '?', '#']).next()?;
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        hostport.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// The acquisition `decide()`: a pure gate over (operator
/// enablement, determination of record, domain allowlist, mode,
/// transport). Every refusal is typed; the order is fixed so the
/// most fundamental refusal wins.
pub fn decide_acquire(
    work: &WorkRecord,
    transport: Transport,
    mode: Mode,
    lane_enabled: bool,
) -> Result<(), Refusal> {
    if !lane_enabled {
        return Err(Refusal::new(
            codes::DISABLED,
            "the acquisition lane is not enabled in policy ([acquisition] enabled = true \
             is the operator's enablement act)"
                .to_string(),
        ));
    }
    match work.determination {
        Determination::Cleared => {}
        Determination::NoRecord => {
            return Err(Refusal::new(
                codes::NO_RECORD,
                format!(
                    "work {} has no determination of record; acquisition requires a \
                     CLEARED determination made before acquisition, fail-closed",
                    work.slug
                ),
            ));
        }
        other => {
            return Err(Refusal::new(
                codes::NOT_CLEARED,
                format!(
                    "work {} is {} of record; only CLEARED works are acquirable (D-246)",
                    work.slug,
                    other.as_str()
                ),
            ));
        }
    }
    let host = host_of(&work.source_url).unwrap_or_default();
    if !ALLOWED_DOMAINS.contains(&host.as_str()) {
        return Err(Refusal::new(
            codes::DOMAIN_REFUSED,
            format!("source host {host:?} is not on the acquisition allowlist {ALLOWED_DOMAINS:?}"),
        ));
    }
    if mode == Mode::Unattended && !S5_BENCHMARK_GREEN {
        return Err(Refusal::new(
            codes::UNATTENDED_BLOCKED,
            format!(
                "unattended acquisition is refused until the S5 benchmark gate is green: \
                 {S5_GATE_EVIDENCE}"
            ),
        ));
    }
    if transport == Transport::SeahawkGui && !S5_BENCHMARK_GREEN {
        return Err(Refusal::new(
            codes::TRANSPORT_BLOCKED,
            format!(
                "the seahawk_gui transport is refused until the S5 benchmark gate is \
                 green: {S5_GATE_EVIDENCE}"
            ),
        ));
    }
    Ok(())
}

/// The quarantine directory layout for one work.
pub fn work_dir(quarantine_root: &Path, slug: &str) -> PathBuf {
    quarantine_root.join(slug)
}

/// The media subdirectory of a work's quarantine directory.
pub fn media_dir(work_dir: &Path) -> PathBuf {
    work_dir.join("media")
}

/// Builds the typed acquisition plan for one work. The plan is
/// the contract a transport executes; it performs no capture.
pub fn plan(work: &WorkRecord, transport: Transport, mode: Mode, quarantine_root: &Path) -> Value {
    let dir = work_dir(quarantine_root, &work.slug);
    json!({
        "slug": work.slug,
        "title": work.title,
        "source_url": work.source_url,
        "determination": work.determination.as_str(),
        "determination_record": work.determination_record,
        "transport": transport.as_str(),
        "mode": mode.as_str(),
        "work_dir": dir.display().to_string(),
        "media_dir": media_dir(&dir).display().to_string(),
        "manifest_path": dir.join("manifest.json").display().to_string(),
        "ingest_packet_path": dir.join("ingest-packet.json").display().to_string(),
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_work_bytes": MAX_WORK_BYTES,
            "max_files_per_work": MAX_FILES_PER_WORK,
        },
        "steps": [
            "transport places captured files into media_dir (download-class only)",
            "seahawk_acquire action=manifest censuses media_dir into manifest.json",
            "seahawk_acquire action=verify re-hashes media_dir against manifest.json",
            "seahawk_acquire action=ingest writes ingest-packet.json for neemu",
            "neemu registers + screens from the packet (existing neemu path)",
            "extraction runs; verified completion is recorded in the manifest",
            "seahawk_acquire action=delete_verified runs the D-248 lifecycle pass",
        ],
    })
}

/// One censused media file, as recorded in the manifest.
#[derive(Debug)]
pub struct FileEntry {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
    pub media_type: String,
    pub capture_method: CaptureMethod,
}

impl FileEntry {
    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "media_type": self.media_type,
            "capture_method": self.capture_method.as_str(),
            "original": self.capture_method.is_original(),
        })
    }
}

/// Sniffs a media type from magic bytes. Extensions are never
/// trusted; an unrecognized signature is not media.
pub fn sniff_media_type(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else if head.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        Some("png")
    } else if head.starts_with(b"GIF8") {
        Some("gif")
    } else if head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        Some("webp")
    } else if head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WAVE" {
        Some("wav")
    } else if head.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        Some("zip")
    } else if head.len() >= 8 && &head[4..8] == b"ftyp" {
        Some("mp4")
    } else if head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        Some("matroska")
    } else if head.starts_with(b"fLaC") {
        Some("flac")
    } else if head.starts_with(b"OggS") {
        Some("ogg")
    } else if head.starts_with(b"ID3") || head.starts_with(&[0xFF, 0xFB]) {
        Some("mp3")
    } else {
        None
    }
}

/// Whether a sniffed type is media neemu's gate can ingest (a
/// ZIP is a container: it must be unpacked to media first).
fn is_ingestible(media_type: &str) -> bool {
    matches!(
        media_type,
        "jpeg" | "png" | "gif" | "webp" | "mp4" | "matroska" | "wav" | "mp3" | "flac" | "ogg"
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Censuses a media directory into file entries, enforcing the
/// lane's size and type limits. `methods` names a capture method
/// per file; files not named default to `Download`. Every file
/// is read whole (bounded by `MAX_FILE_BYTES`) and hashed.
pub fn census_media(
    dir: &Path,
    methods: &BTreeMap<String, CaptureMethod>,
) -> Result<Vec<FileEntry>, Refusal> {
    let mut names: Vec<String> = Vec::new();
    let read = fs::read_dir(dir).map_err(|e| {
        Refusal::new(
            codes::NO_MEDIA,
            format!("media dir {} is unreadable: {e}", dir.display()),
        )
    })?;
    for entry in read {
        let entry = entry.map_err(|e| Refusal::new(codes::NO_MEDIA, format!("census: {e}")))?;
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    if names.is_empty() {
        return Err(Refusal::new(
            codes::NO_MEDIA,
            format!("media dir {} contains no files", dir.display()),
        ));
    }
    if names.len() > MAX_FILES_PER_WORK {
        return Err(Refusal::new(
            codes::TOO_MANY_FILES,
            format!(
                "media dir holds {} files, over the {MAX_FILES_PER_WORK} per-work ceiling",
                names.len()
            ),
        ));
    }
    let mut entries = Vec::with_capacity(names.len());
    let mut total: u64 = 0;
    for name in names {
        let path = dir.join(&name);
        let metadata = fs::metadata(&path)
            .map_err(|e| Refusal::new(codes::NO_MEDIA, format!("cannot stat {name}: {e}")))?;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(Refusal::new(
                codes::FILE_TOO_LARGE,
                format!(
                    "file {name} is {} bytes, over the {MAX_FILE_BYTES} per-file ceiling",
                    metadata.len()
                ),
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|e| Refusal::new(codes::NO_MEDIA, format!("cannot read {name}: {e}")))?;
        let media_type = sniff_media_type(&bytes).ok_or_else(|| {
            Refusal::new(
                codes::TYPE_REFUSED,
                format!(
                    "file {name} has no recognized media signature; extensions are not trusted"
                ),
            )
        })?;
        total = total.saturating_add(metadata.len());
        if total > MAX_WORK_BYTES {
            return Err(Refusal::new(
                codes::WORK_TOO_LARGE,
                format!("work media exceeds the {MAX_WORK_BYTES} per-work ceiling"),
            ));
        }
        let capture_method = methods
            .get(&name)
            .copied()
            .unwrap_or(CaptureMethod::Download);
        entries.push(FileEntry {
            name,
            bytes: metadata.len(),
            sha256: sha256_hex(&bytes),
            media_type: media_type.to_string(),
            capture_method,
        });
    }
    Ok(entries)
}

/// Current unix time in seconds (0 if the clock is pre-epoch).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builds the manifest for one acquired work (D-246 manifest
/// contents: slug, CLEARED record, source URL, capture methods,
/// timestamps, byte counts, SHA-256 per file). The lifecycle
/// block starts at `acquired`; D-248 transitions mutate it in
/// place so the chain of custody survives in one document.
pub fn build_manifest(work: &WorkRecord, entries: &[FileEntry], captured_at: u64) -> Value {
    let total_bytes: u64 = entries.iter().map(|e| e.bytes).sum();
    let originals = entries
        .iter()
        .filter(|e| e.capture_method.is_original())
        .count();
    json!({
        "manifest_version": 1,
        "slug": work.slug,
        "title": work.title,
        "series": work.series,
        "tags": work.tags,
        "tier_claim": work.tier_claim,
        "source_url": work.source_url,
        "determination": {
            "status": work.determination.as_str(),
            "record": work.determination_record,
        },
        "captured_at_unix": captured_at,
        "file_count": entries.len(),
        "original_file_count": originals,
        "screenshot_derived_file_count": entries.len() - originals,
        "total_bytes": total_bytes,
        "files": entries.iter().map(FileEntry::to_json).collect::<Vec<_>>(),
        "lifecycle": {
            "state": "acquired",
            "hold": null,
            "extraction": null,
            "deletion": null,
        },
    })
}

/// Writes a JSON value atomically (temp file + rename) so a
/// crash never leaves a torn manifest.
pub fn write_json_atomic(path: &Path, value: &Value) -> Result<(), Refusal> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| Refusal::new(codes::MANIFEST_INVALID, format!("serialize: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).map_err(|e| {
        Refusal::new(
            codes::MANIFEST_INVALID,
            format!("write {}: {e}", tmp.display()),
        )
    })?;
    fs::rename(&tmp, path).map_err(|e| {
        Refusal::new(
            codes::MANIFEST_INVALID,
            format!("rename to {}: {e}", path.display()),
        )
    })?;
    Ok(())
}

/// Loads a manifest JSON document.
pub fn load_manifest(path: &Path) -> Result<Value, Refusal> {
    let text = fs::read_to_string(path).map_err(|e| {
        Refusal::new(
            codes::MANIFEST_INVALID,
            format!("cannot read manifest {}: {e}", path.display()),
        )
    })?;
    serde_json::from_str(&text).map_err(|e| {
        Refusal::new(
            codes::MANIFEST_INVALID,
            format!("manifest is not valid JSON: {e}"),
        )
    })
}

/// Verifies a media directory against its manifest: every listed
/// file present with matching size, SHA-256, and sniffed type;
/// no unmanifested files; screenshot-derived files never
/// recorded as originals. A work whose files are all
/// screenshot-derived is not original media and fails.
pub fn verify_manifest(manifest: &Value, dir: &Path) -> Result<Value, Refusal> {
    let files = manifest
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Refusal::new(
                codes::MANIFEST_INVALID,
                "manifest has no files array".into(),
            )
        })?;
    let mut originals: usize = 0;
    let mut screenshots: usize = 0;
    let mut total: u64 = 0;
    let mut listed: Vec<String> = Vec::with_capacity(files.len());
    for file in files {
        let name = file.get("name").and_then(Value::as_str).ok_or_else(|| {
            Refusal::new(codes::MANIFEST_INVALID, "manifest file lacks a name".into())
        })?;
        let method = file
            .get("capture_method")
            .and_then(Value::as_str)
            .and_then(CaptureMethod::parse)
            .ok_or_else(|| {
                Refusal::new(
                    codes::MANIFEST_INVALID,
                    format!("file {name} has an unknown capture_method"),
                )
            })?;
        let recorded_original = file
            .get("original")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !method.is_original() {
            screenshots += 1;
            if recorded_original {
                return Err(Refusal::new(
                    codes::SCREENSHOT_MISLABELLED,
                    format!(
                        "file {name} is labelled original but its capture method is \
                         screenshot_derived; screenshots are never original media (D-246)"
                    ),
                ));
            }
        } else {
            originals += 1;
        }
        let path = dir.join(name);
        let bytes = fs::read(&path).map_err(|e| {
            Refusal::new(
                codes::HASH_MISMATCH,
                format!("listed file {name} is missing: {e}"),
            )
        })?;
        let recorded_bytes = file.get("bytes").and_then(Value::as_u64).unwrap_or(0);
        if bytes.len() as u64 != recorded_bytes {
            return Err(Refusal::new(
                codes::HASH_MISMATCH,
                format!(
                    "file {name} is {} bytes, manifest records {recorded_bytes}",
                    bytes.len()
                ),
            ));
        }
        if sha256_hex(&bytes) != file.get("sha256").and_then(Value::as_str).unwrap_or("") {
            return Err(Refusal::new(
                codes::HASH_MISMATCH,
                format!("file {name} fails SHA-256 verification against the manifest"),
            ));
        }
        let sniffed = sniff_media_type(&bytes).unwrap_or("");
        if sniffed != file.get("media_type").and_then(Value::as_str).unwrap_or("") {
            return Err(Refusal::new(
                codes::HASH_MISMATCH,
                format!("file {name} sniffs as {sniffed:?}, manifest records a different type"),
            ));
        }
        total = total.saturating_add(recorded_bytes);
        listed.push(name.to_string());
    }
    let mut on_disk: Vec<String> = Vec::new();
    if let Ok(read) = fs::read_dir(dir) {
        for entry in read.flatten() {
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                on_disk.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    on_disk.sort();
    listed.sort();
    if on_disk != listed {
        return Err(Refusal::new(
            codes::MANIFEST_INVALID,
            "media dir contents differ from the manifest file list (unmanifested or missing files)"
                .into(),
        ));
    }
    if originals == 0 {
        return Err(Refusal::new(
            codes::NO_MEDIA,
            "manifest holds no original media: every file is screenshot-derived (D-246)".into(),
        ));
    }
    Ok(json!({
        "verified": true,
        "files": files.len(),
        "original_files": originals,
        "screenshot_derived_files": screenshots,
        "total_bytes": total,
    }))
}

/// The neemu ingest handoff packet: the exact registration
/// argument set for neemu's existing path, plus the follow-on
/// validate/screen calls. Seahawk produces the packet; neemu's
/// surface is unchanged (D-246).
pub fn ingest_packet(work: &WorkRecord, manifest: &Value, dir: &Path) -> Value {
    let canonical = serde_json::to_string(manifest).unwrap_or_default();
    json!({
        "packet_version": 1,
        "slug": work.slug,
        "manifest_sha256": sha256_hex(canonical.as_bytes()),
        "media_dir": dir.display().to_string(),
        "calls": [
            {
                "tool": "neemu_register_work",
                "arguments": {
                    "title": work.title,
                    "tags": work.tags,
                    "series": work.series,
                    "source": {"kind": "aggregator-scan", "ref": work.source_url},
                    "media_dir": dir.display().to_string(),
                    "tier_claim": work.tier_claim,
                },
            },
            {"tool": "neemu_validate_ingest", "arguments": {"work_id": "$register.work_id"}},
            {
                "tool": "neemu_screen_work",
                "arguments": {
                    "work_id": "$register.work_id",
                    "evidence": {"adult_basis": [{
                        "kind": "age_statement",
                        "detail": work.determination_record.clone(),
                    }]},
                },
            },
        ],
    })
}

/// Records a lifecycle transition in the manifest at `path`
/// (state + optional extraction record + optional hold) and
/// rewrites it atomically. Returns the updated manifest.
pub fn record_lifecycle(
    path: &Path,
    state: &str,
    extraction: Option<Value>,
    hold: Option<String>,
) -> Result<Value, Refusal> {
    let mut manifest = load_manifest(path)?;
    let lifecycle = manifest
        .get_mut("lifecycle")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            Refusal::new(
                codes::MANIFEST_INVALID,
                "manifest has no lifecycle block".into(),
            )
        })?;
    lifecycle.insert("state".to_string(), json!(state));
    if let Some(extraction) = extraction {
        lifecycle.insert("extraction".to_string(), extraction);
    }
    if let Some(hold) = hold {
        lifecycle.insert("hold".to_string(), json!(hold));
    }
    write_json_atomic(path, &manifest)?;
    Ok(manifest)
}

/// D-248 deletion eligibility, checked against the manifest's
/// lifecycle block. Pure: no filesystem access.
pub fn deletion_eligibility(manifest: &Value) -> Result<(), Refusal> {
    let refuse = |why: String| Refusal::new(codes::DELETION_REFUSED, why);
    let lifecycle = manifest.get("lifecycle").ok_or_else(|| {
        refuse("manifest has no lifecycle block; state is unknown, so media is retained".into())
    })?;
    if let Some(hold) = lifecycle.get("hold").and_then(Value::as_str)
        && !hold.is_empty()
    {
        return Err(refuse(format!(
            "work is under a named hold ({hold}); held media is never auto-deleted (D-248)"
        )));
    }
    let state = lifecycle.get("state").and_then(Value::as_str).unwrap_or("");
    if state != "verified_complete" {
        return Err(refuse(format!(
            "lifecycle state is {state:?}, not \"verified_complete\"; incomplete, failed, \
             or unverified media is never auto-deleted (D-248)"
        )));
    }
    let extraction = lifecycle
        .get("extraction")
        .filter(|e| !e.is_null())
        .ok_or_else(|| refuse("no extraction record; verification evidence is absent".into()))?;
    let record_count = extraction
        .get("record_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_hashes = extraction
        .get("output_hashes")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if record_count == 0 || output_hashes == 0 {
        return Err(refuse(
            "extraction record carries no record count or no output hashes; verification \
             against the manifest cannot be shown"
                .into(),
        ));
    }
    Ok(())
}

/// Executes (or, with `dry_run`, only reports) the D-248
/// deletion pass for ONE work: eligibility first, then a full
/// manifest re-verification, then deletion of the media files.
/// The manifest is rewritten with the deletion record (hashes,
/// byte counts, time, freed bytes) — the chain of custody
/// survives the files. Returns the deletion record.
pub fn execute_deletion(work_dir_path: &Path, dry_run: bool, now: u64) -> Result<Value, Refusal> {
    let manifest_path = work_dir_path.join("manifest.json");
    let manifest = load_manifest(&manifest_path)?;
    deletion_eligibility(&manifest)?;
    let dir = media_dir(work_dir_path);
    let verification = verify_manifest(&manifest, &dir)?;
    let files = manifest
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let freed_bytes: u64 = files
        .iter()
        .filter_map(|f| f.get("bytes").and_then(Value::as_u64))
        .sum();
    let record = json!({
        "deleted_at_unix": now,
        "dry_run": dry_run,
        "files_deleted": files.len(),
        "freed_bytes": freed_bytes,
        "verification": verification,
        "files": files.iter().map(|f| json!({
            "name": f.get("name"),
            "bytes": f.get("bytes"),
            "sha256": f.get("sha256"),
        })).collect::<Vec<_>>(),
    });
    if dry_run {
        return Ok(record);
    }
    for file in &files {
        let name = file.get("name").and_then(Value::as_str).unwrap_or("");
        fs::remove_file(dir.join(name)).map_err(|e| {
            Refusal::new(
                codes::DELETION_REFUSED,
                format!("cannot delete {name}: {e}"),
            )
        })?;
    }
    let mut updated = manifest;
    if let Some(lifecycle) = updated.get_mut("lifecycle").and_then(Value::as_object_mut) {
        lifecycle.insert("state".to_string(), json!("media_deleted"));
        lifecycle.insert("deletion".to_string(), record.clone());
    }
    write_json_atomic(&manifest_path, &updated)?;
    Ok(record)
}

/// One orphan-sweep row for a quarantine root: every work dir,
/// its lifecycle state, and whether its media is still present.
/// Report-only by construction (D-248 sweep discipline).
pub fn sweep_report(quarantine_root: &Path) -> Value {
    let mut rows = Vec::new();
    let mut orphans = 0usize;
    if let Ok(read) = fs::read_dir(quarantine_root) {
        let mut dirs: Vec<PathBuf> = read
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .collect();
        dirs.sort();
        for dir in dirs {
            let slug = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let manifest_path = dir.join("manifest.json");
            let (state, has_manifest) = match load_manifest(&manifest_path) {
                Ok(manifest) => (
                    manifest
                        .get("lifecycle")
                        .and_then(|l| l.get("state"))
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                    true,
                ),
                Err(_) => ("no_manifest".to_string(), false),
            };
            let media_present = media_dir(&dir).is_dir()
                && fs::read_dir(media_dir(&dir))
                    .map(|mut r| r.next().is_some())
                    .unwrap_or(false);
            let orphan = media_present && (!has_manifest || state == "media_deleted");
            if orphan {
                orphans += 1;
            }
            rows.push(json!({
                "slug": slug,
                "lifecycle_state": state,
                "has_manifest": has_manifest,
                "media_present": media_present,
                "orphan": orphan,
            }));
        }
    }
    json!({"works": rows, "orphan_count": orphans})
}

/// Capture-method overrides from tool arguments: an object
/// mapping file name → method string. Unknown method strings
/// are a caller error, not a silent default.
pub fn parse_methods(args: &Value) -> Result<BTreeMap<String, CaptureMethod>, Refusal> {
    let mut methods = BTreeMap::new();
    if let Some(obj) = args.get("capture_methods").and_then(Value::as_object) {
        for (name, raw) in obj {
            let method = raw.as_str().and_then(CaptureMethod::parse).ok_or_else(|| {
                Refusal::new(
                    codes::BAD_RECORD,
                    format!("unknown capture method for {name}: {raw}"),
                )
            })?;
            methods.insert(name.clone(), method);
        }
    }
    Ok(methods)
}

/// Whether a work's media census holds at least one ingestible
/// (non-container) original — the shape neemu's media gate
/// accepts. ZIP-only censuses must be unpacked first.
pub fn has_ingestible_original(entries: &[FileEntry]) -> bool {
    entries
        .iter()
        .any(|e| e.capture_method.is_original() && is_ingestible(&e.media_type))
}

/// The same check over a manifest document (the ingest action
/// gates on the verified manifest, not a fresh census).
pub fn manifest_has_ingestible_original(manifest: &Value) -> bool {
    manifest
        .get("files")
        .and_then(Value::as_array)
        .map(|files| {
            files.iter().any(|f| {
                f.get("original").and_then(Value::as_bool).unwrap_or(false)
                    && f.get("media_type")
                        .and_then(Value::as_str)
                        .map(is_ingestible)
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}
