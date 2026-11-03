//! Acquisition lane tests (D-246/D-248). Half validation, half
//! adversarial, per the estate test rule. The Marsha-chan media
//! dir — the lane's one real, hash-verified acquisition — is
//! used as a fixture BY REFERENCE (read-only); everything else
//! runs in per-test temp dirs.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use seahawk::acquisition::{
    CaptureMethod, FileEntry, Mode, Transport, WorkRecord, build_manifest, census_media, codes,
    decide_acquire, deletion_eligibility, execute_deletion, has_ingestible_original, load_manifest,
    record_lifecycle, sniff_media_type, verify_manifest, write_json_atomic,
};
use serde_json::{Value, json};

const MARSHA_MEDIA: &str = "/home/hatch/workspace/corpus-production-20261028/media-real/naive-delinquent-succubus-marsha-chan";
/// Sum of the 116 extracted JPGs (the ZIP container itself is
/// 115,656,598 bytes; both figures verified by Pax at intake).
const MARSHA_EXTRACTED_BYTES: u64 = 115_643_584;

fn jpeg_bytes(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xE0];
    bytes.extend(std::iter::repeat_n(tag, 64));
    bytes
}

fn png_bytes(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend(std::iter::repeat_n(tag, 64));
    bytes
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("seahawk-acq-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn work_json(determination: &str, source_url: &str) -> Value {
    json!({
        "slug": "test-work",
        "title": "Test Work",
        "series": "Original Doujins Series",
        "tags": ["Mind Control"],
        "source_url": source_url,
        "determination": {"status": determination, "record": "determination/test.md"},
        "tier_claim": "A",
    })
}

fn cleared_work() -> WorkRecord {
    WorkRecord::from_json(&work_json(
        "CLEARED",
        "https://doujins.com/gallery/1/test-work-1",
    ))
    .expect("work parses")
}

fn write_media(dir: &Path, files: &[(&str, Vec<u8>)]) {
    fs::create_dir_all(dir).expect("media dir");
    for (name, bytes) in files {
        fs::write(dir.join(name), bytes).expect("write media file");
    }
}

// ---------------------------------------------------------------- validation

#[test]
fn happy_path_decide_plan_manifest_verify() {
    let work = cleared_work();
    assert!(decide_acquire(&work, Transport::BrowserHarness, Mode::Supervised, true).is_ok());

    let root = temp_dir("happy");
    let media = root.join("media");
    write_media(
        &media,
        &[
            ("001.jpg", jpeg_bytes(1)),
            ("002.jpg", jpeg_bytes(2)),
            ("003.png", png_bytes(3)),
        ],
    );
    let mut methods = BTreeMap::new();
    methods.insert("003.png".to_string(), CaptureMethod::ScreenshotDerived);
    let entries = census_media(&media, &methods).expect("census");
    assert_eq!(entries.len(), 3);
    assert!(has_ingestible_original(&entries));

    let manifest = build_manifest(&work, &entries, 1_700_000_000);
    assert_eq!(manifest["file_count"], json!(3));
    assert_eq!(manifest["original_file_count"], json!(2));
    assert_eq!(manifest["screenshot_derived_file_count"], json!(1));
    let report = verify_manifest(&manifest, &media).expect("verify");
    assert_eq!(report["verified"], json!(true));
    assert_eq!(report["original_files"], json!(2));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn marsha_media_fixture_by_reference() {
    let dir = Path::new(MARSHA_MEDIA);
    if !dir.is_dir() {
        return; // fixture lives outside the repo; absence is not a failure here
    }
    let entries = census_media(dir, &BTreeMap::new()).expect("census over real media");
    assert_eq!(entries.len(), 116);
    assert!(entries.iter().all(|e| e.media_type == "jpeg"));
    let total: u64 = entries.iter().map(|e| e.bytes).sum();
    assert_eq!(total, MARSHA_EXTRACTED_BYTES);
    assert!(has_ingestible_original(&entries));
    let manifest = build_manifest(&cleared_work(), &entries, 1_700_000_000);
    let report = verify_manifest(&manifest, dir).expect("verify over real media");
    assert_eq!(report["original_files"], json!(116));
}

#[test]
fn zip_is_a_container_not_ingestible_media() {
    assert_eq!(
        sniff_media_type(&[0x50, 0x4B, 0x03, 0x04, 0, 0]),
        Some("zip")
    );
    let zip_entry = FileEntry {
        name: "work.zip".to_string(),
        bytes: 10,
        sha256: "00".to_string(),
        media_type: "zip".to_string(),
        capture_method: CaptureMethod::Download,
    };
    assert!(!has_ingestible_original(&[zip_entry]));
}

#[test]
fn deletion_happy_path_after_verified_extraction() {
    let root = temp_dir("delete-happy");
    let dir = root.clone();
    let media = dir.join("media");
    write_media(&media, &[("001.jpg", jpeg_bytes(7))]);
    let entries = census_media(&media, &BTreeMap::new()).expect("census");
    let manifest = build_manifest(&cleared_work(), &entries, 1_700_000_000);
    let manifest_path = dir.join("manifest.json");
    write_json_atomic(&manifest_path, &manifest).expect("write manifest");
    record_lifecycle(
        &manifest_path,
        "verified_complete",
        Some(json!({"record_count": 5, "output_hashes": ["aa", "bb"]})),
        None,
    )
    .expect("record lifecycle");

    let dry = execute_deletion(&dir, true, 1_700_000_100).expect("dry run");
    assert_eq!(dry["dry_run"], json!(true));
    assert!(media.join("001.jpg").exists(), "dry run must not delete");

    let record = execute_deletion(&dir, false, 1_700_000_200).expect("real deletion");
    assert_eq!(record["files_deleted"], json!(1));
    assert!(!media.join("001.jpg").exists(), "media file must be gone");
    let after = load_manifest(&manifest_path).expect("manifest survives");
    assert_eq!(after["lifecycle"]["state"], json!("media_deleted"));
    assert_eq!(
        after["lifecycle"]["deletion"]["files"][0]["sha256"], manifest["files"][0]["sha256"],
        "chain of custody: the hash survives the file"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn acquisition_lane_is_disabled_by_default_and_parses_when_enabled() {
    let minimal = "[server]\nagent_token = \"agent-secret\"\n";
    let cfg = seahawk::config::Config::parse(minimal).expect("minimal config");
    assert!(!cfg.acquisition.enabled, "lane must default to disabled");

    let enabled = "[server]\nagent_token = \"agent-secret\"\n\
                   [acquisition]\nenabled = true\nquarantine_dir = \"/tmp/q\"\n";
    let cfg = seahawk::config::Config::parse(enabled).expect("enabled config");
    assert!(cfg.acquisition.enabled);
    assert_eq!(
        cfg.acquisition.quarantine_dir,
        std::path::PathBuf::from("/tmp/q")
    );
}

// ---------------------------------------------------------------- adversarial

#[test]
fn undetermined_work_is_refused() {
    let work = WorkRecord::from_json(&work_json(
        "UNDETERMINED",
        "https://doujins.com/gallery/1/test-work-1",
    ))
    .expect("work parses");
    let refusal = decide_acquire(&work, Transport::BrowserHarness, Mode::Supervised, true)
        .expect_err("must refuse");
    assert_eq!(refusal.code, codes::NOT_CLEARED);
}

#[test]
fn excluded_work_is_refused() {
    let work = WorkRecord::from_json(&work_json(
        "EXCLUDE",
        "https://doujins.com/gallery/1/test-work-1",
    ))
    .expect("work parses");
    let refusal = decide_acquire(&work, Transport::BrowserHarness, Mode::Supervised, true)
        .expect_err("must refuse");
    assert_eq!(refusal.code, codes::NOT_CLEARED);
}

#[test]
fn work_without_a_determination_record_is_refused() {
    let mut raw = work_json("CLEARED", "https://doujins.com/gallery/1/test-work-1");
    raw.as_object_mut().expect("object").remove("determination");
    let work = WorkRecord::from_json(&raw).expect("work parses");
    let refusal = decide_acquire(&work, Transport::BrowserHarness, Mode::Supervised, true)
        .expect_err("must refuse");
    assert_eq!(refusal.code, codes::NO_RECORD);
}

#[test]
fn non_allowlisted_domain_is_refused() {
    let work = WorkRecord::from_json(&work_json(
        "CLEARED",
        "https://example.com/gallery/1/test-work-1",
    ))
    .expect("work parses");
    let refusal = decide_acquire(&work, Transport::BrowserHarness, Mode::Supervised, true)
        .expect_err("must refuse");
    assert_eq!(refusal.code, codes::DOMAIN_REFUSED);
}

#[test]
fn lane_disabled_is_refused() {
    let refusal = decide_acquire(
        &cleared_work(),
        Transport::BrowserHarness,
        Mode::Supervised,
        false,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::DISABLED);
}

#[test]
fn unattended_mode_is_refused_naming_the_s5_gate() {
    let refusal = decide_acquire(
        &cleared_work(),
        Transport::BrowserHarness,
        Mode::Unattended,
        true,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::UNATTENDED_BLOCKED);
    assert!(
        refusal.message.contains("S5"),
        "refusal must name the S5 benchmark gate: {}",
        refusal.message
    );
}

#[test]
fn gui_transport_is_refused_naming_the_s5_gate() {
    let refusal = decide_acquire(
        &cleared_work(),
        Transport::SeahawkGui,
        Mode::Supervised,
        true,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::TRANSPORT_BLOCKED);
    assert!(refusal.message.contains("S5"));
}

#[test]
fn oversize_file_is_refused() {
    let root = temp_dir("oversize");
    let media = root.join("media");
    fs::create_dir_all(&media).expect("media dir");
    let path = media.join("big.jpg");
    fs::write(&path, jpeg_bytes(1)).expect("seed header");
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open sparse file");
    file.set_len(seahawk::acquisition::MAX_FILE_BYTES + 1)
        .expect("set_len");
    drop(file);
    let refusal = census_media(&media, &BTreeMap::new()).expect_err("must refuse");
    assert_eq!(refusal.code, codes::FILE_TOO_LARGE);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn wrong_type_file_is_refused_despite_its_extension() {
    let root = temp_dir("wrong-type");
    let media = root.join("media");
    write_media(
        &media,
        &[("001.jpg", b"this is plain text, not a jpeg".to_vec())],
    );
    let refusal = census_media(&media, &BTreeMap::new()).expect_err("must refuse");
    assert_eq!(refusal.code, codes::TYPE_REFUSED);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn tampered_file_is_caught_by_hash_verify() {
    let root = temp_dir("tamper");
    let media = root.join("media");
    write_media(&media, &[("001.jpg", jpeg_bytes(9))]);
    let entries = census_media(&media, &BTreeMap::new()).expect("census");
    let manifest = build_manifest(&cleared_work(), &entries, 1_700_000_000);
    // Same length, different payload byte: size checks alone
    // would pass this; the hash must not.
    let mut forged = jpeg_bytes(9);
    forged[20] = 0xAB;
    fs::write(media.join("001.jpg"), forged).expect("rewrite file");
    let refusal = verify_manifest(&manifest, &media).expect_err("must refuse");
    assert_eq!(refusal.code, codes::HASH_MISMATCH);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unmanifested_extra_file_is_caught() {
    let root = temp_dir("extra-file");
    let media = root.join("media");
    write_media(&media, &[("001.jpg", jpeg_bytes(4))]);
    let entries = census_media(&media, &BTreeMap::new()).expect("census");
    let manifest = build_manifest(&cleared_work(), &entries, 1_700_000_000);
    fs::write(media.join("002.jpg"), jpeg_bytes(5)).expect("sneak in a file");
    let refusal = verify_manifest(&manifest, &media).expect_err("must refuse");
    assert_eq!(refusal.code, codes::MANIFEST_INVALID);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn screenshot_only_work_is_not_original_media() {
    let root = temp_dir("shots-only");
    let media = root.join("media");
    write_media(&media, &[("001.png", png_bytes(6))]);
    let mut methods = BTreeMap::new();
    methods.insert("001.png".to_string(), CaptureMethod::ScreenshotDerived);
    let entries = census_media(&media, &methods).expect("census");
    let manifest = build_manifest(&cleared_work(), &entries, 1_700_000_000);
    let refusal = verify_manifest(&manifest, &media).expect_err("must refuse");
    assert_eq!(refusal.code, codes::NO_MEDIA);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn screenshot_mislabelled_as_original_is_caught() {
    let root = temp_dir("shot-mislabel");
    let media = root.join("media");
    write_media(
        &media,
        &[("001.png", png_bytes(8)), ("002.jpg", jpeg_bytes(8))],
    );
    let mut methods = BTreeMap::new();
    methods.insert("001.png".to_string(), CaptureMethod::ScreenshotDerived);
    let entries = census_media(&media, &methods).expect("census");
    let mut manifest = build_manifest(&cleared_work(), &entries, 1_700_000_000);
    manifest["files"][0]["original"] = json!(true); // the lie
    let refusal = verify_manifest(&manifest, &media).expect_err("must refuse");
    assert_eq!(refusal.code, codes::SCREENSHOT_MISLABELLED);
    let _ = fs::remove_dir_all(&root);
}

// ------------------------------------------------------- seahawk_fetch (D-503)
//
// All fetch tests run against a loopback HTTP fixture server in
// this file — never the live site. The fetch core takes its
// allowlist and limits as parameters, so the fixture's host
// (127.0.0.1) is the allowlist here and the caps are kilobyte
// scale; the production path passes ALLOWED_DOMAINS and
// FetchLimits::lane().

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use seahawk::acquisition::{
    ALLOWED_DOMAINS, FETCH_USER_AGENT, FetchChain, FetchLimits, Refusal, attach_fetch_provenance,
    build_fetch_client, check_fetch_target, fetch_file, fetch_file_name, fetch_page, media_dir,
    stream_fetch, work_dir,
};

const PAGE_BODY: &[u8] =
    b"<html><head><title>Fixture Page</title></head><body>seahawk fetch fixture</body></html>\n";
const PAGE_SHA256: &str = "9bbad039709cb37c38bbd759d7873dbf1f24bce53f0741b59193ffef92334739";
const LOOPBACK_ALLOWED: [&str; 1] = ["127.0.0.1"];

struct Fixture {
    base: String,
    foreign_base: String,
    hits: Arc<AtomicUsize>,
    user_agents: Arc<Mutex<Vec<String>>>,
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn fixture_route(
    path: &str,
    primary: &str,
    foreign: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let redirect = |to: &str| {
        (
            302,
            vec![("Location".to_string(), to.to_string())],
            Vec::new(),
        )
    };
    match path {
        "/page" => (200, vec![], PAGE_BODY.to_vec()),
        "/dl/photo.jpg" => (200, vec![], jpeg_bytes(42)),
        "/redir-in" => redirect("/dl/photo.jpg"),
        "/redir-off" => redirect("http://evil.example.net/dl/photo.jpg"),
        // D-504 designated-host routes: `foreign` is the same
        // listener under its localhost name, so a hop to it
        // changes the host STRING (127.0.0.1 -> localhost) —
        // which is what the chain rule keys on — while
        // staying reachable on one listener.
        "/redir-designated" => redirect(&format!("{foreign}/dl/photo.jpg")),
        "/redir-designated-back" => redirect(&format!("{foreign}/redir-back")),
        "/redir-second-foreign" => redirect(&format!("{foreign}/redir-second")),
        "/redir-back" => redirect(&format!("{primary}/dl/photo.jpg")),
        "/redir-second" => redirect("http://127.0.0.3:9/dl/photo.jpg"),
        "/big" => (200, vec![], vec![0xAA; 8192]),
        "/missing" => (404, vec![], b"no such fixture".to_vec()),
        "/slow" => {
            std::thread::sleep(Duration::from_secs(2));
            (200, vec![], PAGE_BODY.to_vec())
        }
        _ if path.starts_with("/chain") => {
            let n: usize = path
                .rsplit('=')
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if n >= 7 {
                (200, vec![], PAGE_BODY.to_vec())
            } else {
                redirect(&format!("/chain?n={}", n + 1))
            }
        }
        _ => (404, vec![], b"unknown fixture path".to_vec()),
    }
}

fn handle_fixture(
    mut stream: std::net::TcpStream,
    hits: Arc<AtomicUsize>,
    user_agents: Arc<Mutex<Vec<String>>>,
    primary: String,
    foreign: String,
) {
    hits.fetch_add(1, Ordering::SeqCst);
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let head = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    break String::from_utf8_lossy(&buf[..pos]).into_owned();
                }
            }
            Err(_) => return,
        }
    };
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
    for line in head.lines() {
        if line.to_ascii_lowercase().starts_with("user-agent:")
            && let Some((_, value)) = line.split_once(':')
        {
            user_agents
                .lock()
                .expect("user-agent lock")
                .push(value.trim().to_string());
        }
    }
    let (status, headers, body) = fixture_route(&path, &primary, &foreign);
    let reason = match status {
        200 => "OK",
        302 => "Found",
        _ => "Not Found",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .into_bytes();
    for (name, value) in &headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&body);
    let _ = stream.write_all(&out);
}

fn start_fixture() -> Fixture {
    // One listener, two host strings for it: the primary base
    // (127.0.0.1, the test allowlist) and the foreign base
    // (localhost, which resolves to the same listener but is
    // NOT on the allowlist) so D-504 designated-host chains
    // can actually complete. A second loopback address
    // (127.0.0.2) was tried first and is not connectable in
    // this sandbox; the host-string distinction is what the
    // chain rule keys on, so localhost carries the test.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let port = listener.local_addr().expect("fixture addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let foreign_base = format!("http://localhost:{port}");
    let hits = Arc::new(AtomicUsize::new(0));
    let user_agents = Arc::new(Mutex::new(Vec::new()));
    let thread_hits = hits.clone();
    let thread_uas = user_agents.clone();
    let thread_primary = base.clone();
    let thread_foreign = foreign_base.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let hits = thread_hits.clone();
            let uas = thread_uas.clone();
            let primary = thread_primary.clone();
            let foreign = thread_foreign.clone();
            std::thread::spawn(move || handle_fixture(stream, hits, uas, primary, foreign));
        }
    });
    Fixture {
        base,
        foreign_base,
        hits,
        user_agents,
    }
}

fn test_limits() -> FetchLimits {
    FetchLimits {
        max_file_bytes: 1_000_000,
        max_work_bytes: 1_000_000,
        total_timeout: Duration::from_secs(10),
    }
}

fn dir_listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|read| {
            read.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

// ------------------------------------------------------- fetch validation

#[test]
fn seahawk_fetch_transport_roundtrips_and_plans() {
    assert_eq!(
        Transport::parse("seahawk_fetch"),
        Some(Transport::SeahawkFetch)
    );
    assert_eq!(Transport::SeahawkFetch.as_str(), "seahawk_fetch");
    let work = cleared_work();
    assert!(decide_acquire(&work, Transport::SeahawkFetch, Mode::Supervised, true).is_ok());
    let root = temp_dir("fetch-plan");
    let plan = seahawk::acquisition::plan(&work, Transport::SeahawkFetch, Mode::Supervised, &root);
    assert_eq!(plan["transport"], json!("seahawk_fetch"));
    assert!(
        plan["steps"][0]
            .as_str()
            .expect("step")
            .contains("action=fetch"),
        "a seahawk_fetch plan must name the fetch action: {}",
        plan["steps"][0]
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_page_stores_evidence_outside_the_media_census() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-page");
    let payload = fetch_page(
        &client,
        &cleared_work(),
        &format!("{}/page", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect("page fetch");
    assert_eq!(payload["kind"], json!("page"));
    assert_eq!(payload["status"], json!(200));
    assert_eq!(payload["bytes"], json!(PAGE_BODY.len()));
    assert_eq!(payload["sha256"], json!(PAGE_SHA256));

    let dir = work_dir(&root, "test-work");
    let stored = fs::read(dir.join("page.html")).expect("page.html evidence stored");
    assert_eq!(
        stored, PAGE_BODY,
        "stored evidence is the fetched body, byte for byte"
    );
    // The evidence lives in the work dir, NOT the media dir:
    // the manifest census sees no media at all.
    let refusal = census_media(&media_dir(&dir), &BTreeMap::new()).expect_err("no media");
    assert_eq!(refusal.code, codes::NO_MEDIA);
    assert_eq!(dir_listing(&dir), vec!["page.html".to_string()]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_file_lands_bytes_and_manifest_censuses_them() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-file");
    let work = cleared_work();
    let payload = fetch_file(
        &client,
        &work,
        &format!("{}/dl/photo.jpg", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect("file fetch");
    assert_eq!(payload["file_name"], json!("photo.jpg"));
    assert_eq!(payload["bytes"], json!(68));
    let dir = work_dir(&root, "test-work");
    let entries = census_media(&media_dir(&dir), &BTreeMap::new()).expect("census");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "photo.jpg");
    assert_eq!(
        json!(entries[0].sha256),
        payload["sha256"],
        "the manifest census hash must match the fetch hash"
    );
    let manifest = build_manifest(&work, &entries, 1_700_000_000);
    assert_eq!(manifest["file_count"], json!(1));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_redirect_within_allowlist_is_followed() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-redir-in");
    let payload = fetch_file(
        &client,
        &cleared_work(),
        &format!("{}/redir-in", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect("redirected file fetch");
    assert!(
        payload["final_url"]
            .as_str()
            .expect("final url")
            .ends_with("/dl/photo.jpg"),
        "final URL is the redirect target: {}",
        payload["final_url"]
    );
    assert_eq!(
        payload["file_name"],
        json!("photo.jpg"),
        "the file name derives from the FINAL URL"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_sends_the_browser_user_agent() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-ua");
    fetch_page(
        &client,
        &cleared_work(),
        &format!("{}/page", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect("page fetch");
    let agents = fixture.user_agents.lock().expect("user-agent lock");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0], FETCH_USER_AGENT);
    let _ = fs::remove_dir_all(&root);
}

// ------------------------------------------------------- fetch adversarial

#[test]
fn fetch_unattended_seahawk_fetch_is_refused_by_the_mode_gate() {
    // The S5 unattended refusal is mode-based, not
    // transport-based: it must fire for seahawk_fetch unchanged.
    let refusal = decide_acquire(
        &cleared_work(),
        Transport::SeahawkFetch,
        Mode::Unattended,
        true,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::UNATTENDED_BLOCKED);
}

#[test]
fn fetch_lane_disabled_is_refused() {
    let refusal = decide_acquire(
        &cleared_work(),
        Transport::SeahawkFetch,
        Mode::Supervised,
        false,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::DISABLED);
}

#[test]
fn fetch_undetermined_work_is_refused() {
    let work = WorkRecord::from_json(&work_json(
        "UNDETERMINED",
        "https://doujins.com/gallery/1/test-work-1",
    ))
    .expect("work parses");
    let refusal = decide_acquire(&work, Transport::SeahawkFetch, Mode::Supervised, true)
        .expect_err("must refuse");
    assert_eq!(refusal.code, codes::NOT_CLEARED);
}

#[test]
fn fetch_non_allowlist_host_is_refused_before_any_socket() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let mut sink = |_chunk: &[u8]| -> Result<(), Refusal> { Ok(()) };
    let refusal = stream_fetch(
        &client,
        &format!("{}/page", fixture.base),
        &["doujins.com"],
        &test_limits(),
        None,
        FetchChain::AllowlistOnly,
        &mut sink,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::DOMAIN_REFUSED);
    assert_eq!(
        fixture.hits.load(Ordering::SeqCst),
        0,
        "a non-allowlisted host is refused before any socket use"
    );
}

#[test]
fn fetch_page_redirect_off_allowlist_is_refused() {
    // D-504: a PAGE chain never leaves the allowlist, so the
    // same off-allowlist redirect a file chain may designate
    // still refuses here.
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-page-redir-off");
    let refusal = fetch_page(
        &client,
        &cleared_work(),
        &format!("{}/redir-off", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::REDIRECT_REFUSED);
    assert!(
        refusal.message.contains("evil.example.net"),
        "the refusal names the off-allowlist host: {}",
        refusal.message
    );
    let dir = work_dir(&root, "test-work");
    assert!(
        dir_listing(&dir).is_empty(),
        "no partial evidence after a redirect refusal"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_file_completes_on_the_first_site_designated_host() {
    // D-504: a file chain that starts allowlisted may
    // complete on the first non-allowlist host the site's
    // route designates, and that host is recorded.
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-designated");
    let payload = fetch_file(
        &client,
        &cleared_work(),
        &format!("{}/redir-designated", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect("designated file fetch");
    assert_eq!(payload["file_name"], json!("photo.jpg"));
    assert_eq!(payload["site_designated_host"], json!("localhost"));
    assert!(
        fixture.hits.load(Ordering::SeqCst) >= 2,
        "the designated host was actually contacted (initial + designated hop)"
    );
    let dir = work_dir(&root, "test-work");
    let history = fs::read_to_string(dir.join("fetch-history.json")).expect("fetch history");
    assert!(
        history.contains("localhost"),
        "the designated host is in the fetch history: {history}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_file_return_to_allowlist_keeps_the_designation_record() {
    // D-504: returning to the allowlist is fine, and the
    // designation already made stays on the record even
    // though the final host is allowlisted.
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-designated-back");
    let payload = fetch_file(
        &client,
        &cleared_work(),
        &format!("{}/redir-designated-back", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect("returning file fetch");
    assert_eq!(payload["file_name"], json!("photo.jpg"));
    assert!(
        payload["final_url"]
            .as_str()
            .expect("final url")
            .starts_with(&fixture.base),
        "the chain ended back on the allowlist: {}",
        payload["final_url"]
    );
    assert_eq!(payload["site_designated_host"], json!("localhost"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_file_second_foreign_host_is_refused() {
    // D-504: a hop to a DIFFERENT non-allowlist host after a
    // designation refuses, before any socket to that host.
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-second-foreign");
    let refusal = fetch_file(
        &client,
        &cleared_work(),
        &format!("{}/redir-second-foreign", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::REDIRECT_REFUSED);
    assert!(
        refusal.message.contains("127.0.0.3"),
        "the refusal names the second foreign host: {}",
        refusal.message
    );
    let dir = work_dir(&root, "test-work");
    assert!(
        dir_listing(&media_dir(&dir)).is_empty(),
        "no partial and no landed file after a redirect refusal"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_file_cold_foreign_start_is_refused() {
    // D-504: the designation must come from the site's route,
    // not the caller — a caller-supplied foreign start refuses
    // before any socket use, for files exactly as for pages.
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-cold-foreign");
    let refusal = fetch_file(
        &client,
        &cleared_work(),
        &format!("{}/dl/photo.jpg", fixture.foreign_base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::DOMAIN_REFUSED);
    assert_eq!(
        fixture.hits.load(Ordering::SeqCst),
        0,
        "a cold foreign start is refused before any socket use"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_manifest_records_the_site_designated_host() {
    // D-504: the designated host reaches the manifest through
    // fetch_provenance, not only through the fetch result.
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-manifest-prov");
    let work = cleared_work();
    fetch_file(
        &client,
        &work,
        &format!("{}/redir-designated", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect("designated file fetch");
    let dir = work_dir(&root, "test-work");
    let entries = census_media(&media_dir(&dir), &BTreeMap::new()).expect("census");
    let mut manifest = build_manifest(&work, &entries, 1_700_000_000);
    attach_fetch_provenance(&mut manifest, &dir);
    assert_eq!(
        manifest["fetch_provenance"][0]["site_designated_host"],
        json!("localhost")
    );
    assert_eq!(
        manifest["fetch_provenance"][0]["file_name"],
        json!("photo.jpg")
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_redirect_chain_over_the_ceiling_is_refused() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-chain");
    let refusal = fetch_page(
        &client,
        &cleared_work(),
        &format!("{}/chain?n=0", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::REDIRECT_REFUSED);
    let dir = work_dir(&root, "test-work");
    assert!(
        dir_listing(&dir).is_empty(),
        "no partial evidence after a redirect refusal"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_file_cap_breach_mid_stream_leaves_no_partial() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-file-cap");
    let limits = FetchLimits {
        max_file_bytes: 1024,
        ..test_limits()
    };
    let refusal = fetch_file(
        &client,
        &cleared_work(),
        &format!("{}/big", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &limits,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::FILE_TOO_LARGE);
    let dir = work_dir(&root, "test-work");
    assert!(
        dir_listing(&media_dir(&dir)).is_empty(),
        "a mid-stream cap breach leaves no partial file"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_work_cap_breach_is_refused_and_leaves_no_partial() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-work-cap");
    let dir = work_dir(&root, "test-work");
    let mdir = media_dir(&dir);
    fs::create_dir_all(&mdir).expect("media dir");
    fs::write(mdir.join("existing.bin"), vec![0u8; 900]).expect("seed existing media");
    let limits = FetchLimits {
        max_work_bytes: 1000,
        ..test_limits()
    };
    let refusal = fetch_file(
        &client,
        &cleared_work(),
        &format!("{}/big", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &limits,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::WORK_TOO_LARGE);
    assert_eq!(
        dir_listing(&mdir),
        vec!["existing.bin".to_string()],
        "only the pre-existing file remains; the partial is deleted"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_non_2xx_is_refused_with_the_status_recorded() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let root = temp_dir("fetch-404");
    let refusal = fetch_page(
        &client,
        &cleared_work(),
        &format!("{}/missing", fixture.base),
        &root,
        &LOOPBACK_ALLOWED,
        &test_limits(),
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::FETCH_STATUS);
    assert!(
        refusal.message.contains("404"),
        "the refusal records the status: {}",
        refusal.message
    );
    let dir = work_dir(&root, "test-work");
    assert!(
        dir_listing(&dir).is_empty(),
        "no evidence stored for a refused status"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn fetch_https_preflight_refuses_http_and_foreign_hosts() {
    assert!(check_fetch_target("https://new.lewd.ninja/game/1-x", &ALLOWED_DOMAINS).is_ok());
    assert!(check_fetch_target("https://doujins.com/gallery/1-x", &ALLOWED_DOMAINS).is_ok());
    let http = check_fetch_target("http://new.lewd.ninja/game/1-x", &ALLOWED_DOMAINS)
        .expect_err("plain HTTP must refuse");
    assert_eq!(http.code, codes::DOMAIN_REFUSED);
    let foreign = check_fetch_target("https://example.com/game/1-x", &ALLOWED_DOMAINS)
        .expect_err("foreign host must refuse");
    assert_eq!(foreign.code, codes::DOMAIN_REFUSED);
    let lookalike = check_fetch_target("https://new.lewd.ninja.example.com/x", &ALLOWED_DOMAINS)
        .expect_err("suffix lookalike must refuse: hosts match whole, never by suffix");
    assert_eq!(lookalike.code, codes::DOMAIN_REFUSED);
}

#[test]
fn fetch_file_name_refuses_traversal_and_accepts_plain_names() {
    assert_eq!(
        fetch_file_name("https://h.example/dl/photo.jpg?dl=1").expect("plain name"),
        "photo.jpg"
    );
    assert_eq!(
        fetch_file_name("https://h.example/dl/my%20file.jpg").expect("decoded name"),
        "my file.jpg"
    );
    for url in [
        "https://h.example/%2e%2e%2fsecret",
        "https://h.example/dl/a%2Fb.jpg",
        "https://h.example/dl/a%5Cb.jpg",
        "https://h.example/dl/",
        "https://h.example/%2e%2e",
        "https://h.example/dl/%zz.jpg",
    ] {
        let refusal = fetch_file_name(url).expect_err("must refuse");
        assert_eq!(refusal.code, codes::BAD_RECORD, "url {url}");
    }
}

#[test]
fn fetch_timeout_is_bounded() {
    let fixture = start_fixture();
    let client = build_fetch_client().expect("client");
    let limits = FetchLimits {
        total_timeout: Duration::from_millis(500),
        ..test_limits()
    };
    let mut sink = |_chunk: &[u8]| -> Result<(), Refusal> { Ok(()) };
    let refusal = stream_fetch(
        &client,
        &format!("{}/slow", fixture.base),
        &LOOPBACK_ALLOWED,
        &limits,
        None,
        FetchChain::AllowlistOnly,
        &mut sink,
    )
    .expect_err("must refuse");
    assert_eq!(refusal.code, codes::FETCH_FAILED);
}

#[test]
fn deletion_is_refused_for_unverified_failed_and_held_states() {
    let manifest_for = |state: &str, hold: Option<&str>| {
        json!({
            "lifecycle": {
                "state": state,
                "hold": hold,
                "extraction": {"record_count": 5, "output_hashes": ["aa"]},
                "deletion": null,
            }
        })
    };
    for state in ["acquired", "registered", "extracted_unverified", "failed"] {
        let refusal = deletion_eligibility(&manifest_for(state, None)).expect_err("must refuse");
        assert_eq!(refusal.code, codes::DELETION_REFUSED, "state {state}");
    }
    let held = deletion_eligibility(&manifest_for(
        "verified_complete",
        Some("owner eye verification"),
    ))
    .expect_err("held media must refuse");
    assert_eq!(held.code, codes::DELETION_REFUSED);
    // And the one eligible shape passes the pure gate.
    assert!(deletion_eligibility(&manifest_for("verified_complete", None)).is_ok());
}
