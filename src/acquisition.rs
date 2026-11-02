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
//! widen the lane. The one transport that fetches bytes itself is
//! `primo_fetch` (D-503): the broker process fetches over HTTPS
//! through the fetch core at the bottom of this module, under
//! exactly the same `decide()` gate and caps as every other
//! transport, with the D-504 chain rule (file chains start
//! allowlisted and may complete on the first site-designated
//! host; page chains never leave the allowlist).
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
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    pub const FETCH_FAILED: &str = "seahawk_acquisition_fetch_failed";
    pub const FETCH_STATUS: &str = "seahawk_acquisition_fetch_status";
    pub const REDIRECT_REFUSED: &str = "seahawk_acquisition_redirect_refused";
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
/// Connect timeout for the `primo_fetch` transport (D-503).
pub const FETCH_CONNECT_TIMEOUT_SECS: u64 = 15;
/// Redirect ceiling for the `primo_fetch` transport (D-503):
/// at most this many hops are followed, and only while every
/// hop's host stays on the acquisition allowlist.
pub const FETCH_MAX_REDIRECTS: usize = 5;
/// Per-fetch total time budget for the `primo_fetch` transport
/// (D-503): the connect, every redirect hop, and the body
/// stream share one deadline.
pub const FETCH_TOTAL_TIMEOUT_SECS: u64 = 300;
/// A mainstream browser User-Agent for the `primo_fetch`
/// transport: the allowlisted sites serve their pages to
/// browser-class agents.
pub const FETCH_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
/// The evidence file a `kind=page` fetch writes in a work's
/// quarantine dir. It is deliberately NOT in the media dir: a
/// captured source page is provenance evidence, never media,
/// and the manifest census must not pick it up.
pub const PAGE_EVIDENCE_FILE: &str = "page.html";

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
    /// The broker process itself fetches over HTTPS (D-503) —
    /// for deployments whose host has no refused fetch route.
    PrimoFetch,
    /// Seahawk's own GUI tools — gated on the S5 benchmark.
    SeahawkGui,
}

impl Transport {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "browser_harness" => Some(Self::BrowserHarness),
            "primo_fetch" => Some(Self::PrimoFetch),
            "seahawk_gui" => Some(Self::SeahawkGui),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BrowserHarness => "browser_harness",
            Self::PrimoFetch => "primo_fetch",
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
    let capture_step = match transport {
        Transport::PrimoFetch => {
            "seahawk_acquire action=fetch (primo_fetch transport) \
             fetches captured files into media_dir (download-class only); kind=page \
             fetches store page.html evidence in the work dir, outside the media census"
        }
        _ => "transport places captured files into media_dir (download-class only)",
    };
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
            capture_step,
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
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

// ---------------------------------------------------------------------
// primo_fetch transport (D-503): the broker process itself fetches.
//
// Every other transport places files into quarantine from outside
// the process; this one fetches over HTTPS from inside it, for
// deployments (primo) whose network route carries no fetch
// refusal. The gate strength is identical: the verb runs
// `decide_acquire()` first, then `check_fetch_target()` as a
// pre-flight, and `stream_fetch` re-checks every host it is about
// to touch — the initial URL and every redirect hop — against the
// allowlist before the socket work for that hop begins.

/// The `primo_fetch` transport's working limits: the lane caps
/// plus the per-fetch time budget. `lane()` carries the policy
/// values; the fields are parameters so tests can exercise the
/// caps against loopback fixtures at kilobyte scale.
#[derive(Clone, Copy, Debug)]
pub struct FetchLimits {
    pub max_file_bytes: u64,
    pub max_work_bytes: u64,
    pub total_timeout: Duration,
}

impl FetchLimits {
    /// The lane's policy limits (D-480 caps, D-503 timeouts).
    pub fn lane() -> Self {
        Self {
            max_file_bytes: MAX_FILE_BYTES,
            max_work_bytes: MAX_WORK_BYTES,
            total_timeout: Duration::from_secs(FETCH_TOTAL_TIMEOUT_SECS),
        }
    }
}

/// The redirect-chain policy for a `primo_fetch` fetch. The
/// chain always starts on an allowlisted host (a cold foreign
/// start is refused before any socket use); what differs by
/// kind is what a redirect off the allowlist may do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchChain {
    /// Every hop must stay on the allowlist: a redirect to
    /// any other host is refused (D-503; `kind=page`).
    AllowlistOnly,
    /// The chain may complete on the first non-allowlist host
    /// the site's own route designates (D-504; `kind=file`):
    /// hops to a *different* non-allowlist host are refused,
    /// and returning to the allowlist is fine. The designation
    /// comes from the site's route, never from the caller.
    SiteDesignated,
}

/// What one completed fetch moved: byte count, content hash,
/// the URL the redirect chain ended on, its final status, and
/// — for a `kind=file` chain that left the allowlist — the
/// first site-designated host the transfer completed through
/// (D-504; `None` when the chain never left the allowlist).
#[derive(Debug)]
pub struct FetchOutcome {
    pub bytes: u64,
    pub final_url: String,
    pub sha256: String,
    pub status: u16,
    pub site_designated_host: Option<String>,
}

/// Builds the `primo_fetch` transport's HTTP client. This is
/// the only client in the broker built with TLS (see the
/// Cargo.toml note): the downstream client keeps its own
/// unchanged, loopback-only construction in `downstream.rs`.
/// Redirects are disabled here — `stream_fetch` follows them
/// manually so every hop's host is checked against the
/// allowlist before the hop is taken.
pub fn build_fetch_client() -> Result<reqwest::blocking::Client, Refusal> {
    reqwest::blocking::Client::builder()
        .user_agent(FETCH_USER_AGENT)
        .connect_timeout(Duration::from_secs(FETCH_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(FETCH_TOTAL_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            Refusal::new(
                codes::FETCH_FAILED,
                format!("cannot build the primo_fetch client: {e}"),
            )
        })
}

/// Exact-host allowlist membership: hosts are compared whole
/// (never by suffix) and case-insensitively — `host_of` output
/// is already lowercased; configured entries are policy data.
pub fn fetch_host_allowed(host: &str, allowed_hosts: &[&str]) -> bool {
    allowed_hosts.iter().any(|d| d.eq_ignore_ascii_case(host))
}

/// The `primo_fetch` pre-flight over a caller-supplied URL, run
/// by the verb before any client is built or socket touched:
/// HTTPS only, and the host must be on the acquisition
/// allowlist.
pub fn check_fetch_target(url: &str, allowed_hosts: &[&str]) -> Result<(), Refusal> {
    let scheme = url.split("://").next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(Refusal::new(
            codes::DOMAIN_REFUSED,
            format!(
                "fetch URL {url:?} is not an HTTPS URL; the primo_fetch transport \
                 fetches over HTTPS only"
            ),
        ));
    }
    let host = host_of(url)
        .ok_or_else(|| Refusal::new(codes::BAD_RECORD, format!("fetch URL {url:?} has no host")))?;
    if !fetch_host_allowed(&host, allowed_hosts) {
        return Err(Refusal::new(
            codes::DOMAIN_REFUSED,
            format!("fetch host {host:?} is not on the acquisition allowlist {allowed_hosts:?}"),
        ));
    }
    Ok(())
}

/// Percent-decodes one URL path segment. Malformed escapes are
/// a caller error, never a silent pass-through.
fn percent_decode(segment: &str) -> Result<String, Refusal> {
    let bad = || {
        Refusal::new(
            codes::BAD_RECORD,
            format!("URL path segment {segment:?} has malformed percent-encoding"),
        )
    };
    let raw = segment.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hex = raw.get(i + 1..i + 3).ok_or_else(bad)?;
            let hex = std::str::from_utf8(hex).map_err(|_| bad())?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| bad())?;
            out.push(byte);
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| bad())
}

/// Derives the media-dir file name for a `kind=file` fetch from
/// the FINAL URL of the redirect chain: the last path segment,
/// percent-decoded, then validated as a plain file name.
/// Anything that could traverse out of the media dir —
/// separators (raw or encoded), dot segments, control bytes,
/// an empty or over-long name — is refused, never sanitised
/// into a different name the caller did not ask for.
pub fn fetch_file_name(final_url: &str) -> Result<String, Refusal> {
    let refuse = |why: &str| {
        Refusal::new(
            codes::BAD_RECORD,
            format!("cannot derive a safe file name from final URL {final_url:?}: {why}"),
        )
    };
    let path = final_url.split(['?', '#']).next().unwrap_or("");
    let segment = path.rsplit('/').next().unwrap_or("");
    if segment.is_empty() {
        return Err(refuse("the URL path names no file"));
    }
    let name = percent_decode(segment)?;
    if name.is_empty() || name == "." || name == ".." {
        return Err(refuse("the decoded name is empty or a dot segment"));
    }
    if name
        .bytes()
        .any(|b| b == b'/' || b == b'\\' || b < 0x20 || b == 0x7f)
    {
        return Err(refuse(
            "the decoded name contains a path separator or control byte",
        ));
    }
    if name.len() > 255 {
        return Err(refuse("the decoded name exceeds 255 bytes"));
    }
    Ok(name)
}

/// Total bytes currently held in a media dir (0 when the dir
/// does not exist). Sizes only — contents are never read, so
/// this stays cheap even at the work cap.
pub fn media_dir_bytes(dir: &Path) -> u64 {
    let Ok(read) = fs::read_dir(dir) else {
        return 0;
    };
    let mut total: u64 = 0;
    for entry in read.flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            total = total.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0));
        }
    }
    total
}

/// Streams one fetch for the `primo_fetch` transport: a GET on
/// `url`, following redirects manually (at most
/// `FETCH_MAX_REDIRECTS` hops). The chain always starts on an
/// allowlisted host — a cold foreign start is refused before
/// any socket is opened — and every hop's host is decided
/// before the hop is taken: under `FetchChain::AllowlistOnly`
/// any off-allowlist hop is refused; under
/// `FetchChain::SiteDesignated` (D-504) the first
/// off-allowlist hop designates that host for the rest of the
/// chain (hops within it, and hops back to the allowlist, are
/// fine) while a hop to a *different* non-allowlist host is
/// refused. The body streams to `sink` in bounded chunks
/// while both caps are enforced mid-stream
/// (`limits.max_file_bytes` for this file; `work_budget`,
/// when given, is the work's remaining byte allowance under
/// `limits.max_work_bytes`). One deadline
/// (`limits.total_timeout`) covers the whole chain, enforced
/// per request and re-checked at every hop. On any refusal the
/// caller owns deleting the partial output.
pub fn stream_fetch(
    client: &reqwest::blocking::Client,
    url: &str,
    allowed_hosts: &[&str],
    limits: &FetchLimits,
    work_budget: Option<u64>,
    chain: FetchChain,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), Refusal>,
) -> Result<FetchOutcome, Refusal> {
    let deadline = Instant::now() + limits.total_timeout;
    let first_host = host_of(url)
        .ok_or_else(|| Refusal::new(codes::BAD_RECORD, format!("fetch URL {url:?} has no host")))?;
    if !fetch_host_allowed(&first_host, allowed_hosts) {
        return Err(Refusal::new(
            codes::DOMAIN_REFUSED,
            format!(
                "fetch host {first_host:?} is not on the acquisition allowlist \
                 {allowed_hosts:?}"
            ),
        ));
    }
    let mut current = url.to_string();
    let mut hops = 0usize;
    // The one non-allowlist host this chain may complete
    // through, once the site's own route designates it
    // (D-504). `None` until the first off-allowlist hop.
    let mut designated: Option<String> = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Refusal::new(
                codes::FETCH_FAILED,
                format!(
                    "fetch of {url:?} exceeded its {}s total budget",
                    limits.total_timeout.as_secs()
                ),
            ));
        }
        let mut response = client
            .get(&current)
            .timeout(remaining)
            .send()
            .map_err(|e| {
                Refusal::new(
                    codes::FETCH_FAILED,
                    format!("fetch of {current:?} failed: {e}"),
                )
            })?;
        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if let Some(location) = location {
                if hops >= FETCH_MAX_REDIRECTS {
                    return Err(Refusal::new(
                        codes::REDIRECT_REFUSED,
                        format!(
                            "fetch of {url:?} exceeded the {FETCH_MAX_REDIRECTS}-redirect \
                             ceiling"
                        ),
                    ));
                }
                let next = reqwest::Url::parse(&current)
                    .and_then(|base| base.join(&location))
                    .map_err(|e| {
                        Refusal::new(
                            codes::REDIRECT_REFUSED,
                            format!(
                                "redirect from {current:?} has an unusable Location \
                                 {location:?}: {e}"
                            ),
                        )
                    })?
                    .to_string();
                let next_host = host_of(&next).unwrap_or_default();
                if !fetch_host_allowed(&next_host, allowed_hosts) {
                    match chain {
                        FetchChain::AllowlistOnly => {
                            return Err(Refusal::new(
                                codes::REDIRECT_REFUSED,
                                format!(
                                    "redirect from {current:?} points at host \
                                     {next_host:?}, which is not on the acquisition \
                                     allowlist {allowed_hosts:?}; the hop was not taken"
                                ),
                            ));
                        }
                        FetchChain::SiteDesignated => match &designated {
                            None => {
                                // The site's own route
                                // designates this host for the
                                // rest of the chain (D-504).
                                designated = Some(next_host);
                            }
                            Some(host) if host.eq_ignore_ascii_case(&next_host) => {}
                            Some(host) => {
                                return Err(Refusal::new(
                                    codes::REDIRECT_REFUSED,
                                    format!(
                                        "redirect from {current:?} points at a second \
                                         non-allowlist host {next_host:?}; this chain \
                                         already designated {host:?} (D-504), so the \
                                         hop was not taken"
                                    ),
                                ));
                            }
                        },
                    }
                }
                hops += 1;
                current = next;
                continue;
            }
            // A redirect status with no usable Location is a
            // final answer, and not a success: fall through to
            // the status refusal below.
        }
        if !status.is_success() {
            return Err(Refusal::new(
                codes::FETCH_STATUS,
                format!(
                    "fetch of {current:?} ended with HTTP status {}",
                    status.as_u16()
                ),
            ));
        }
        let mut hasher = Sha256::new();
        let mut bytes: u64 = 0;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = response.read(&mut buffer).map_err(|e| {
                Refusal::new(
                    codes::FETCH_FAILED,
                    format!("fetch of {current:?} failed mid-body: {e}"),
                )
            })?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            bytes = bytes.saturating_add(read as u64);
            if bytes > limits.max_file_bytes {
                return Err(Refusal::new(
                    codes::FILE_TOO_LARGE,
                    format!(
                        "fetched file exceeds the {} per-file ceiling mid-stream; the \
                         partial capture is deleted",
                        limits.max_file_bytes
                    ),
                ));
            }
            if let Some(budget) = work_budget
                && bytes > budget
            {
                return Err(Refusal::new(
                    codes::WORK_TOO_LARGE,
                    format!(
                        "fetched file exceeds the work's remaining byte allowance \
                         ({budget} of the {} per-work ceiling); the partial capture is \
                         deleted",
                        limits.max_work_bytes
                    ),
                ));
            }
            hasher.update(chunk);
            sink(chunk)?;
        }
        let digest = hasher.finalize();
        return Ok(FetchOutcome {
            bytes,
            final_url: current,
            sha256: hex_encode(&digest),
            status: status.as_u16(),
            site_designated_host: designated,
        });
    }
}

/// Runs `stream_fetch` into the partial-capture file at
/// `part_path`, deleting the partial on any refusal (cap
/// breach, redirect refusal, transport failure) so a failed
/// fetch never leaves a censused or half-written file behind.
fn fetch_to_part(
    client: &reqwest::blocking::Client,
    url: &str,
    allowed_hosts: &[&str],
    limits: &FetchLimits,
    work_budget: Option<u64>,
    chain: FetchChain,
    part_path: &Path,
) -> Result<FetchOutcome, Refusal> {
    let mut file = fs::File::create(part_path).map_err(|e| {
        Refusal::new(
            codes::FETCH_FAILED,
            format!("cannot create partial capture {}: {e}", part_path.display()),
        )
    })?;
    let result = stream_fetch(
        client,
        url,
        allowed_hosts,
        limits,
        work_budget,
        chain,
        &mut |chunk| {
            file.write_all(chunk).map_err(|e| {
                Refusal::new(
                    codes::FETCH_FAILED,
                    format!("cannot write partial capture {}: {e}", part_path.display()),
                )
            })
        },
    );
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(part_path);
    }
    result
}

/// `kind=page` fetch (D-503): stores the fetched page as
/// `page.html` evidence in the work's quarantine dir — NOT in
/// the media dir, so the manifest census never picks it up.
/// The body streams to a `.part` file first and is renamed
/// into place only on success; a refused or failed fetch
/// leaves no partial evidence behind. A page chain never
/// leaves the allowlist (D-504): any off-allowlist redirect
/// is refused, and `site_designated_host` is always null.
pub fn fetch_page(
    client: &reqwest::blocking::Client,
    work: &WorkRecord,
    url: &str,
    quarantine_root: &Path,
    allowed_hosts: &[&str],
    limits: &FetchLimits,
) -> Result<Value, Refusal> {
    let dir = work_dir(quarantine_root, &work.slug);
    fs::create_dir_all(&dir).map_err(|e| {
        Refusal::new(
            codes::FETCH_FAILED,
            format!("cannot create work dir {}: {e}", dir.display()),
        )
    })?;
    let part_path = dir.join(format!("{PAGE_EVIDENCE_FILE}.part"));
    let outcome = fetch_to_part(
        client,
        url,
        allowed_hosts,
        limits,
        None,
        FetchChain::AllowlistOnly,
        &part_path,
    )?;
    let stored = dir.join(PAGE_EVIDENCE_FILE);
    fs::rename(&part_path, &stored).map_err(|e| {
        let _ = fs::remove_file(&part_path);
        Refusal::new(
            codes::FETCH_FAILED,
            format!("cannot store fetched page at {}: {e}", stored.display()),
        )
    })?;
    Ok(json!({
        "action": "fetch",
        "kind": "page",
        "slug": work.slug,
        "transport": Transport::PrimoFetch.as_str(),
        "url": url,
        "final_url": outcome.final_url,
        "status": outcome.status,
        "bytes": outcome.bytes,
        "sha256": outcome.sha256,
        "site_designated_host": outcome.site_designated_host,
        "stored_path": stored.display().to_string(),
    }))
}

/// Appends one file-fetch record to the work's
/// `fetch-history.json` (created on first use). Best effort
/// by design: provenance must never fail a fetch that already
/// succeeded, so every failure here is swallowed. The
/// manifest action attaches this history to the manifest as
/// `fetch_provenance` (see `attach_fetch_provenance`), which
/// is how a D-504 site-designated host reaches the manifest.
fn record_fetch_history(work_dir_path: &Path, record: Value) {
    let path = work_dir_path.join("fetch-history.json");
    let mut history = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or_else(|| json!({"fetches": []}));
    if let Some(fetches) = history.get_mut("fetches").and_then(Value::as_array_mut) {
        fetches.push(record);
    }
    let _ = write_json_atomic(&path, &history);
}

/// Attaches a work's fetch history (written by `fetch_file`
/// runs) to a manifest document under `fetch_provenance`.
/// Absent or unreadable history is not an error — most works
/// have none, and a manifest must never fail for want of
/// provenance.
pub fn attach_fetch_provenance(manifest: &mut Value, work_dir_path: &Path) {
    let Ok(text) = fs::read_to_string(work_dir_path.join("fetch-history.json")) else {
        return;
    };
    let Ok(history) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    if let (Some(fetches), Some(obj)) = (history.get("fetches"), manifest.as_object_mut()) {
        obj.insert("fetch_provenance".to_string(), fetches.clone());
    }
}

/// `kind=file` fetch (D-503, chain rule D-504): streams the
/// body into the work's media dir under the name derived from
/// the final URL, with the lane caps enforced mid-stream (see
/// `stream_fetch`). The chain must start on an allowlisted
/// host and may complete on the first non-allowlist host the
/// site's route designates; that host is recorded in the
/// result's `site_designated_host` and appended to the work's
/// `fetch-history.json`, which the manifest action attaches to
/// the manifest as `fetch_provenance` — so every designated
/// host is on the record twice over. An existing file with
/// the derived name is never overwritten — re-fetching over a
/// captured (possibly manifested) file is a caller error,
/// refused after the partial is deleted.
pub fn fetch_file(
    client: &reqwest::blocking::Client,
    work: &WorkRecord,
    url: &str,
    quarantine_root: &Path,
    allowed_hosts: &[&str],
    limits: &FetchLimits,
) -> Result<Value, Refusal> {
    let dir = work_dir(quarantine_root, &work.slug);
    let mdir = media_dir(&dir);
    fs::create_dir_all(&mdir).map_err(|e| {
        Refusal::new(
            codes::FETCH_FAILED,
            format!("cannot create media dir {}: {e}", mdir.display()),
        )
    })?;
    let prior = media_dir_bytes(&mdir);
    let work_budget = Some(limits.max_work_bytes.saturating_sub(prior));
    let part_path = mdir.join(".fetch.part");
    let outcome = fetch_to_part(
        client,
        url,
        allowed_hosts,
        limits,
        work_budget,
        FetchChain::SiteDesignated,
        &part_path,
    )?;
    let name = match fetch_file_name(&outcome.final_url) {
        Ok(name) => name,
        Err(refusal) => {
            let _ = fs::remove_file(&part_path);
            return Err(refusal);
        }
    };
    let stored = mdir.join(&name);
    if stored.exists() {
        let _ = fs::remove_file(&part_path);
        return Err(Refusal::new(
            codes::BAD_RECORD,
            format!("media dir already holds a file named {name:?}; refusing to overwrite it"),
        ));
    }
    fs::rename(&part_path, &stored).map_err(|e| {
        let _ = fs::remove_file(&part_path);
        Refusal::new(
            codes::FETCH_FAILED,
            format!("cannot store fetched file at {}: {e}", stored.display()),
        )
    })?;
    record_fetch_history(
        &dir,
        json!({
            "kind": "file",
            "url": url,
            "final_url": outcome.final_url,
            "site_designated_host": outcome.site_designated_host,
            "bytes": outcome.bytes,
            "sha256": outcome.sha256,
            "file_name": name,
            "fetched_at_unix": unix_now(),
        }),
    );
    Ok(json!({
        "action": "fetch",
        "kind": "file",
        "slug": work.slug,
        "transport": Transport::PrimoFetch.as_str(),
        "url": url,
        "final_url": outcome.final_url,
        "status": outcome.status,
        "bytes": outcome.bytes,
        "sha256": outcome.sha256,
        "site_designated_host": outcome.site_designated_host,
        "file_name": name,
        "stored_path": stored.display().to_string(),
    }))
}
