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
