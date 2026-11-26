//! Take and pose artifacts (DESIGN-ANIM §1): the frozen,
//! shippable animation unit for the Blender provider's v2
//! surface.
//!
//! A take binds authored animation — per-channel key sets
//! (bone transforms and shape-key values under one addressing
//! grammar), Grease Pencil frame tracks, and an optional bake
//! header — to exactly one scene file by hash. A pose is a
//! single-frame slice of the same channel grammar. Both are
//! canonical JSON with an embedded SHA-256 over the canonical
//! bytes of everything else, 6-decimal-string numerics, and
//! Tiger-Style bounds that refuse rather than truncate — the
//! v1 artifact discipline (`stroke` module) carried over
//! unchanged, with the animation bounds and the v2 excluded
//! set (DESIGN-ANIM §1.5, §3) added.
//!
//! This module is the broker-side validator plus the two pure
//! transforms the surface needs: `export_take` (the D-1397
//! timeline-compiler input form, lossless or refused) and
//! `action_digest` (the gate instrument of DESIGN-ANIM §6.1).
//! Write/execute-class blender ops validate here before the
//! downstream is contacted; `blender.take_validate` serves
//! this module directly and never touches the scene.

use std::collections::HashSet;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::stroke::{EXCLUDED_KEYS, canonical_bytes, content_hash};

pub const TAKE_SCHEMA: &str = "seahawk.take/v2";
pub const POSE_SCHEMA: &str = "seahawk.pose/v2";
pub const EXPORT_SCHEMA: &str = "seahawk.take-export/v2";
pub const RIGBUILD_SCHEMA: &str = "seahawk.rigbuild/v1";
pub const MAX_RIG_BONES: usize = 512;
pub const MAX_RIG_CONSTRAINTS: usize = 512;
pub const MAX_RIG_WEIGHT_GROUPS: usize = 256;
pub const MAX_RIG_VERTICES: usize = 200_000;
pub const RIG_CONSTRAINT_TYPES: [&str; 9] = [
    "IK",
    "COPY_LOCATION",
    "COPY_ROTATION",
    "COPY_SCALE",
    "DAMPED_TRACK",
    "TRACK_TO",
    "LIMIT_LOCATION",
    "LIMIT_ROTATION",
    "LIMIT_SCALE",
];

/// Hard bounds (DESIGN-ANIM §1.5): an artifact outside them
/// is refused, never truncated. Sized from the real rigs: the
/// Prima retrofit's 172 bones × ≤10 transform components is
/// ~1,720 channels worst case, far under the channel cap.
pub const MAX_CHANNELS: usize = 4096;
pub const MAX_KEYS_PER_CHANNEL: usize = 4096;
pub const MAX_KEYS_TOTAL: usize = 1_000_000;
pub const MAX_FRAMES_SPAN: u64 = 3600;
pub const MAX_GP_TRACKS: usize = 64;
pub const MAX_GP_REFS_TOTAL: usize = 3600;
pub const MAX_POSE_CHANNELS: usize = 4096;
pub const MAX_ID_CHARS: usize = 128;
pub const MAX_NAME_CHARS: usize = 256;

/// Blender's full interpolation enum (DESIGN-ANIM §1.2). A key
/// carries the interpolation evaluation will read; anything
/// outside this set is not Blender data and is refused.
pub const INTERPS: [&str; 13] = [
    "CONSTANT", "LINEAR", "BEZIER", "SINE", "QUAD", "CUBIC", "QUART", "QUINT", "EXPO", "CIRC",
    "BACK", "BOUNCE", "ELASTIC",
];

/// The interpolations whose evaluation reads a per-key easing
/// mode; for all others the easing field must be null.
const EASING_INTERPS: [&str; 8] = [
    "SINE", "QUAD", "CUBIC", "QUART", "QUINT", "EXPO", "CIRC", "BACK",
];

pub const EASINGS: [&str; 4] = ["AUTO", "EASE_IN", "EASE_OUT", "EASE_IN_OUT"];

pub const HANDLE_TYPES: [&str; 5] = ["AUTO_CLAMPED", "AUTO", "VECTOR", "ALIGNED", "FREE"];

pub const EXTRAPOLATIONS: [&str; 2] = ["CONSTANT", "LINEAR"];

/// The v2 excluded set (DESIGN-ANIM §3), enforced by name on
/// top of the v1 set: drivers, NLA, and F-curve modifiers are
/// evaluation-time state outside the key set, so a take that
/// claims them is not self-contained and is refused. The scan
/// skips the bake header's `settings` subtree — settings are a
/// verbatim transcription of a simulation's property set, not
/// artifact structure.
pub const V2_EXCLUDED_KEYS: [&str; 6] = [
    "driver",
    "drivers",
    "fcurve_modifiers",
    "modifier",
    "modifiers",
    "nla",
];

/// What validation learned about a take.
#[derive(Clone, Debug)]
pub struct TakeInfo {
    pub id: String,
    pub sha256: String,
    pub channels: usize,
    pub keys: usize,
    pub gp_tracks: usize,
    pub gp_refs: usize,
    pub baked: bool,
}

/// What validation learned about a pose.
#[derive(Clone, Debug)]
pub struct PoseInfo {
    pub id: String,
    pub sha256: String,
    pub channels: usize,
}

fn refuse(message: String) -> String {
    message
}

/// A 6-decimal string per D2: optional minus, digits, a point,
/// exactly six fractional digits (mirrors `stroke`'s rule).
fn is_decimal6(text: &str) -> bool {
    let (digits, frac) = match text.split_once('.') {
        Some(parts) => parts,
        None => return false,
    };
    let digits = digits.strip_prefix('-').unwrap_or(digits);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && frac.len() == 6
        && frac.bytes().all(|b| b.is_ascii_digit())
}

fn decimal6(text: &str) -> Option<f64> {
    is_decimal6(text).then(|| text.parse::<f64>().ok())?
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Scans every object key outside `skip_settings` subtrees
/// against the v1 + v2 exclusion sets; returns the first
/// excluded key found.
fn find_excluded(value: &Value, in_bake_settings: bool) -> Option<&'static str> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if !in_bake_settings {
                    if let Some(hit) = EXCLUDED_KEYS.iter().find(|ex| **ex == key.as_str()) {
                        return Some(hit);
                    }
                    if let Some(hit) = V2_EXCLUDED_KEYS.iter().find(|ex| **ex == key.as_str()) {
                        return Some(hit);
                    }
                }
                let child_in_settings = key == "settings"
                    && map.contains_key("settings_sha256")
                    && map.contains_key("system");
                if let Some(hit) = find_excluded(child, in_bake_settings || child_in_settings) {
                    return Some(hit);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| find_excluded(item, in_bake_settings)),
        _ => None,
    }
}

fn check_keys(object: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), String> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(refuse(format!(
                "{what} carries unknown key {key:?}; the v2 schema admits only {allowed:?}"
            )));
        }
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a str, String> {
    match object.get(key).and_then(Value::as_str) {
        Some(text) if !text.is_empty() && text.chars().count() <= MAX_NAME_CHARS => Ok(text),
        _ => Err(refuse(format!(
            "{what}.{key} must be a non-empty string of at most {MAX_NAME_CHARS} characters"
        ))),
    }
}

fn required_id(object: &Map<String, Value>, what: &str) -> Result<String, String> {
    match object.get("id").and_then(Value::as_str) {
        Some(text) if !text.is_empty() && text.chars().count() <= MAX_ID_CHARS => {
            Ok(text.to_string())
        }
        _ => Err(refuse(format!(
            "{what}.id must be a non-empty string of at most {MAX_ID_CHARS} characters"
        ))),
    }
}

fn check_created_by(object: &Map<String, Value>, what: &str) -> Result<(), String> {
    if let Some(created_by) = object.get("created_by") {
        match created_by.as_str() {
            Some(text) if text.chars().count() <= MAX_NAME_CHARS => {}
            _ => {
                return Err(refuse(format!("{what}.created_by must be a short string")));
            }
        }
    }
    Ok(())
}

fn check_sha256_field(object: &Map<String, Value>, what: &str) -> Result<String, String> {
    let Some(claimed) = object.get("sha256").and_then(Value::as_str) else {
        return Err(refuse(format!(
            "{what}.sha256 is required (hex, over the canonical bytes)"
        )));
    };
    if !is_sha256_hex(claimed) {
        return Err(refuse(format!(
            "{what}.sha256 must be 64 lowercase hex characters"
        )));
    }
    Ok(claimed.to_string())
}

fn check_content_hash(envelope: &Value, claimed: &str, what: &str) -> Result<(), String> {
    let computed = content_hash(envelope).expect("envelope is an object");
    if computed != claimed {
        return Err(refuse(format!(
            "{what}.sha256 does not match the canonical content hash (claimed {claimed}, \
             computed {computed}); the artifact is refused, not repaired"
        )));
    }
    Ok(())
}

/// The channel-address grammar (DESIGN-ANIM §1.2): a path is
/// a bare transform property, a pose-bone transform path, or
/// a shape-key value path. Anything else is not an address
/// capture could have transcribed, and is refused by name.
fn check_path(path: &str, what: &str) -> Result<(), String> {
    const PROPS: [&str; 4] = ["location", "rotation_euler", "rotation_quaternion", "scale"];
    if PROPS.contains(&path) {
        return Ok(());
    }
    for (prefix, tail) in [("pose.bones[\"", None), ("key_blocks[\"", Some(".value"))] {
        if let Some(rest) = path.strip_prefix(prefix)
            && let Some((name, after)) = rest.split_once("\"]")
            && !name.is_empty()
            && !name.contains('"')
        {
            match tail {
                None if PROPS.contains(&after.strip_prefix('.').unwrap_or("")) => {
                    return Ok(());
                }
                Some(expected) if after == expected => return Ok(()),
                _ => {}
            }
        }
    }
    Err(refuse(format!(
        "{what}.path {path:?} is not a v2 channel address (a bare transform property, \
         pose.bones[\"<bone>\"].<property>, or key_blocks[\"<block>\"].value)"
    )))
}

/// The canonical address of one channel, used by the bake
/// header's channel list and the action digest:
/// `<id.type>:<id.name>|<path>|<index>`.
pub fn channel_address(id_type: &str, id_name: &str, path: &str, index: u64) -> String {
    format!("{id_type}:{id_name}|{path}|{index}")
}

struct ChannelHead {
    address: String,
}

/// Validates a channel's addressing head (id, slot, path,
/// index, extrapolation where the schema carries it) and
/// returns its canonical address.
fn check_channel_head(
    channel: &Map<String, Value>,
    what: &str,
    with_extrapolation: bool,
) -> Result<ChannelHead, String> {
    let allowed: &[&str] = if with_extrapolation {
        &["id", "slot", "path", "index", "extrapolation", "keys"]
    } else {
        &[
            "id",
            "slot",
            "path",
            "index",
            "value",
            "handle_left",
            "handle_right",
            "handle_left_type",
            "handle_right_type",
        ]
    };
    check_keys(channel, allowed, what)?;
    let Some(id) = channel.get("id").and_then(Value::as_object) else {
        return Err(refuse(format!("{what}.id must be an object")));
    };
    check_keys(id, &["type", "name"], &format!("{what}.id"))?;
    let id_type = required_string(id, "type", &format!("{what}.id"))?;
    let id_name = required_string(id, "name", &format!("{what}.id"))?;
    match channel.get("slot") {
        None | Some(Value::Null) => {}
        Some(slot) => {
            if slot.as_str().is_none_or(|s| s.is_empty()) {
                return Err(refuse(format!(
                    "{what}.slot must be null or a non-empty string"
                )));
            }
        }
    }
    let path = required_string(channel, "path", what)?;
    check_path(path, what)?;
    let Some(index) = channel.get("index").and_then(Value::as_u64) else {
        return Err(refuse(format!("{what}.index must be an integer")));
    };
    if index > 3 {
        return Err(refuse(format!(
            "{what}.index {index} is outside 0..=3 (the array-component bound)"
        )));
    }
    if with_extrapolation {
        match channel.get("extrapolation").and_then(Value::as_str) {
            Some(extra) if EXTRAPOLATIONS.contains(&extra) => {}
            _ => {
                return Err(refuse(format!(
                    "{what}.extrapolation must be CONSTANT | LINEAR"
                )));
            }
        }
    }
    Ok(ChannelHead {
        address: channel_address(id_type, id_name, path, index),
    })
}

fn check_handle_pair(
    key: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Option<(String, String)>, String> {
    match key.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(pair) => {
            let Some(parts) = pair.as_array() else {
                return Err(refuse(format!(
                    "{what}.{field} must be null or [frame, value]"
                )));
            };
            if parts.len() != 2 {
                return Err(refuse(format!(
                    "{what}.{field} must hold exactly 2 components"
                )));
            }
            let mut out = Vec::new();
            for part in parts {
                match part.as_str().and_then(decimal6) {
                    Some(_) => out.push(part.as_str().expect("checked").to_string()),
                    None => {
                        return Err(refuse(format!(
                            "{what}.{field} components must be 6-decimal strings (D2)"
                        )));
                    }
                }
            }
            Ok(Some((out[0].clone(), out[1].clone())))
        }
    }
}

fn check_handle_type(
    key: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Option<String>, String> {
    match key.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => match value.as_str() {
            Some(text) if HANDLE_TYPES.contains(&text) => Ok(Some(text.to_string())),
            _ => Err(refuse(format!(
                "{what}.{field} must be null or one of {HANDLE_TYPES:?}"
            ))),
        },
    }
}

fn check_easing_param(
    key: &Map<String, Value>,
    field: &str,
    required: bool,
    interp: &str,
    what: &str,
) -> Result<(), String> {
    match key.get(field) {
        Some(Value::String(text)) if decimal6(text).is_some() => {
            if !required {
                return Err(refuse(format!(
                    "{what}.{field} is set but interpolation {interp} does not read it; \
                     a key carries exactly the data its evaluation reads (DESIGN-ANIM §1.2)"
                )));
            }
            Ok(())
        }
        None | Some(Value::Null) => {
            if required {
                Err(refuse(format!(
                    "{what}.{field} is required by interpolation {interp}; a key that omits \
                     data evaluation would read is malformed (DESIGN-ANIM §1.2)"
                )))
            } else {
                Ok(())
            }
        }
        _ => Err(refuse(format!(
            "{what}.{field} must be null or a 6-decimal string"
        ))),
    }
}

/// Validates one keyframe point end to end: the key carries
/// everything its evaluation reads — handles and handle types
/// for BEZIER, easing mode for the easing family, the easing
/// parameters for BACK / ELASTIC — and nothing else.
fn check_key(key: &Value, what: &str) -> Result<f64, String> {
    let Some(key) = key.as_object() else {
        return Err(refuse(format!("{what} must be an object")));
    };
    check_keys(
        key,
        &[
            "frame",
            "value",
            "interp",
            "easing",
            "handle_left",
            "handle_right",
            "handle_left_type",
            "handle_right_type",
            "back",
            "amplitude",
            "period",
        ],
        what,
    )?;
    let Some(frame) = key.get("frame").and_then(Value::as_str).and_then(decimal6) else {
        return Err(refuse(format!(
            "{what}.frame must be a 6-decimal string (D2)"
        )));
    };
    if key
        .get("value")
        .and_then(Value::as_str)
        .and_then(decimal6)
        .is_none()
    {
        return Err(refuse(format!(
            "{what}.value must be a 6-decimal string (D2)"
        )));
    }
    let Some(interp) = key.get("interp").and_then(Value::as_str) else {
        return Err(refuse(format!("{what}.interp must be a string")));
    };
    if !INTERPS.contains(&interp) {
        return Err(refuse(format!(
            "{what}.interp {interp:?} is not in Blender's interpolation enum {INTERPS:?}"
        )));
    }
    match key.get("easing") {
        Some(Value::String(text)) => {
            if !EASING_INTERPS.contains(&interp) {
                return Err(refuse(format!(
                    "{what}.easing is set but interpolation {interp} does not read an \
                     easing mode"
                )));
            }
            if !EASINGS.contains(&text.as_str()) {
                return Err(refuse(format!(
                    "{what}.easing {text:?} must be one of {EASINGS:?}"
                )));
            }
        }
        None | Some(Value::Null) => {
            if EASING_INTERPS.contains(&interp) {
                return Err(refuse(format!(
                    "{what}.easing is required by interpolation {interp}"
                )));
            }
        }
        _ => {
            return Err(refuse(format!("{what}.easing must be null or a string")));
        }
    }
    let handle_left = check_handle_pair(key, "handle_left", what)?;
    let handle_right = check_handle_pair(key, "handle_right", what)?;
    let handle_left_type = check_handle_type(key, "handle_left_type", what)?;
    let handle_right_type = check_handle_type(key, "handle_right_type", what)?;
    if interp == "BEZIER" {
        if handle_left.is_none()
            || handle_right.is_none()
            || handle_left_type.is_none()
            || handle_right_type.is_none()
        {
            return Err(refuse(format!(
                "{what} is a BEZIER key without full handle data; handles are carried, \
                 never recomputed (DESIGN-ANIM §3)"
            )));
        }
    } else if handle_left.is_some()
        || handle_right.is_some()
        || handle_left_type.is_some()
        || handle_right_type.is_some()
    {
        return Err(refuse(format!(
            "{what} carries handle data but interpolation {interp} does not read handles"
        )));
    }
    check_easing_param(key, "back", interp == "BACK", interp, what)?;
    check_easing_param(key, "amplitude", interp == "ELASTIC", interp, what)?;
    check_easing_param(key, "period", interp == "ELASTIC", interp, what)?;
    Ok(frame)
}

struct Frames {
    start: u64,
    end: u64,
    fps_num: u64,
    fps_base: String,
}

fn check_frames(value: &Value, what: &str) -> Result<Frames, String> {
    let Some(object) = value.as_object() else {
        return Err(refuse(format!("{what} must be an object")));
    };
    check_keys(object, &["start", "end", "fps_num", "fps_base"], what)?;
    let (Some(start), Some(end)) = (
        object.get("start").and_then(Value::as_u64),
        object.get("end").and_then(Value::as_u64),
    ) else {
        return Err(refuse(format!(
            "{what}.start and {what}.end must be non-negative integers"
        )));
    };
    if end < start {
        return Err(refuse(format!(
            "{what}.end {end} precedes {what}.start {start}"
        )));
    }
    if end - start > MAX_FRAMES_SPAN {
        return Err(refuse(format!(
            "{what} spans {} frames; the bound is {MAX_FRAMES_SPAN} \
             (refused, not truncated)",
            end - start
        )));
    }
    let Some(fps_num) = object.get("fps_num").and_then(Value::as_u64) else {
        return Err(refuse(format!("{what}.fps_num must be an integer")));
    };
    if fps_num == 0 {
        return Err(refuse(format!("{what}.fps_num must be at least 1")));
    }
    let Some(fps_base) = object.get("fps_base").and_then(Value::as_str) else {
        return Err(refuse(format!(
            "{what}.fps_base must be a 6-decimal string (the raw fps pair, DESIGN-ANIM §1.1)"
        )));
    };
    match decimal6(fps_base) {
        Some(base) if base > 0.0 => {}
        _ => {
            return Err(refuse(format!(
                "{what}.fps_base must be a positive 6-decimal string"
            )));
        }
    }
    Ok(Frames {
        start,
        end,
        fps_num,
        fps_base: fps_base.to_string(),
    })
}

fn check_scene_sha(object: &Map<String, Value>, what: &str) -> Result<String, String> {
    let Some(target) = object.get("target").and_then(Value::as_object) else {
        return Err(refuse(format!("{what}.target must be an object")));
    };
    match target.get("scene_sha256").and_then(Value::as_str) {
        Some(text) if is_sha256_hex(text) => Ok(text.to_string()),
        _ => Err(refuse(format!(
            "{what}.target.scene_sha256 must be 64 lowercase hex characters \
             (the scene-hash binding, DESIGN-ANIM §1.1)"
        ))),
    }
}

/// Validates one take envelope end to end: exclusion scan,
/// schema shape, bounds, channel grammar, key completeness,
/// GP track references, the bake header (with its settings
/// hash and channel cross-check), and the embedded content
/// hash. The error names the failure — the validator is the
/// enforcement of DESIGN-ANIM §3, not a convention.
pub fn validate_take(envelope: &Value) -> Result<TakeInfo, String> {
    if let Some(excluded) = find_excluded(envelope, false) {
        return Err(refuse(format!(
            "take carries excluded construct {excluded:?}: drivers, NLA, F-curve \
             modifiers, and the v1 interactive-engine features are policy-excluded \
             because a take must be self-contained key data (DESIGN-ANIM §3)"
        )));
    }
    let Some(object) = envelope.as_object() else {
        return Err(refuse("take must be a JSON object".to_string()));
    };
    check_keys(
        object,
        &[
            "schema",
            "id",
            "created_by",
            "target",
            "frames",
            "channels",
            "gp_tracks",
            "bake",
            "sha256",
        ],
        "take",
    )?;
    if object.get("schema").and_then(Value::as_str) != Some(TAKE_SCHEMA) {
        return Err(refuse(format!("take.schema must be {TAKE_SCHEMA:?}")));
    }
    let id = required_id(object, "take")?;
    check_created_by(object, "take")?;
    check_scene_sha(object, "take")?;
    let Some(target) = object.get("target").and_then(Value::as_object) else {
        return Err(refuse("take.target must be an object".to_string()));
    };
    check_keys(target, &["scene_sha256", "rig"], "take.target")?;
    match target.get("rig") {
        None | Some(Value::Null) => {}
        Some(rig) => {
            if rig.as_str().is_none_or(|s| s.is_empty()) {
                return Err(refuse(
                    "take.target.rig must be null or a non-empty string".to_string(),
                ));
            }
        }
    }
    let frames = check_frames(
        object.get("frames").ok_or("take.frames is required")?,
        "take.frames",
    )?;
    let Some(channels) = object.get("channels").and_then(Value::as_array) else {
        return Err(refuse("take.channels must be an array".to_string()));
    };
    if channels.len() > MAX_CHANNELS {
        return Err(refuse(format!(
            "take carries {} channels; the bound is {MAX_CHANNELS} \
             (refused, not truncated)",
            channels.len()
        )));
    }
    let mut addresses: HashSet<String> = HashSet::new();
    let mut total_keys: usize = 0;
    for (index, channel) in channels.iter().enumerate() {
        let what = format!("take.channels[{index}]");
        let Some(channel) = channel.as_object() else {
            return Err(refuse(format!("{what} must be an object")));
        };
        let head = check_channel_head(channel, &what, true)?;
        if !addresses.insert(head.address.clone()) {
            return Err(refuse(format!(
                "take carries channel {} twice; two channels writing one address \
                 in one take is a refusal (DESIGN-ANIM §1.2)",
                head.address
            )));
        }
        let Some(keys) = channel.get("keys").and_then(Value::as_array) else {
            return Err(refuse(format!("{what}.keys must be an array")));
        };
        if keys.is_empty() {
            return Err(refuse(format!(
                "{what}.keys must not be empty (a channel with no keys is not a channel)"
            )));
        }
        if keys.len() > MAX_KEYS_PER_CHANNEL {
            return Err(refuse(format!(
                "{what} carries {} keys; the bound is {MAX_KEYS_PER_CHANNEL} \
                 (refused, not truncated)",
                keys.len()
            )));
        }
        total_keys = total_keys
            .checked_add(keys.len())
            .ok_or_else(|| refuse("take key count overflowed".to_string()))?;
        if total_keys > MAX_KEYS_TOTAL {
            return Err(refuse(format!(
                "take carries more than {MAX_KEYS_TOTAL} keys in total \
                 (refused, not truncated)"
            )));
        }
        let mut previous: Option<f64> = None;
        for (key_index, key) in keys.iter().enumerate() {
            let key_what = format!("{what}.keys[{key_index}]");
            let frame = check_key(key, &key_what)?;
            if frame < frames.start as f64 || frame > frames.end as f64 {
                return Err(refuse(format!(
                    "{key_what}.frame {frame} lies outside the take range \
                     {}..={}; a key outside the range is a refusal, not a clip \
                     (DESIGN-ANIM §1.1)",
                    frames.start, frames.end
                )));
            }
            if let Some(prev) = previous
                && frame <= prev
            {
                return Err(refuse(format!(
                    "{key_what}.frame {frame} does not ascend past {prev}; canonical \
                     form stores keys in ascending frame order (DESIGN-ANIM §1.2)"
                )));
            }
            previous = Some(frame);
        }
    }
    let gp_tracks = object
        .get("gp_tracks")
        .and_then(Value::as_array)
        .ok_or("take.gp_tracks is required (an empty array when the take has no GP)")?;
    if gp_tracks.len() > MAX_GP_TRACKS {
        return Err(refuse(format!(
            "take carries {} GP tracks; the bound is {MAX_GP_TRACKS} \
             (refused, not truncated)",
            gp_tracks.len()
        )));
    }
    let mut total_refs: usize = 0;
    for (index, track) in gp_tracks.iter().enumerate() {
        let what = format!("take.gp_tracks[{index}]");
        let Some(track) = track.as_object() else {
            return Err(refuse(format!("{what} must be an object")));
        };
        check_keys(track, &["object", "layer", "frames"], &what)?;
        required_string(track, "object", &what)?;
        required_string(track, "layer", &what)?;
        let Some(track_frames) = track.get("frames").and_then(Value::as_array) else {
            return Err(refuse(format!("{what}.frames must be an array")));
        };
        if track_frames.is_empty() {
            return Err(refuse(format!(
                "{what}.frames must not be empty (a track with no frames binds nothing)"
            )));
        }
        let mut previous: Option<u64> = None;
        for (ref_index, entry) in track_frames.iter().enumerate() {
            let entry_what = format!("{what}.frames[{ref_index}]");
            let Some(entry) = entry.as_object() else {
                return Err(refuse(format!("{entry_what} must be an object")));
            };
            check_keys(entry, &["frame", "artifact"], &entry_what)?;
            let Some(frame) = entry.get("frame").and_then(Value::as_u64) else {
                return Err(refuse(format!(
                    "{entry_what}.frame must be a non-negative integer"
                )));
            };
            if frame < frames.start || frame > frames.end {
                return Err(refuse(format!(
                    "{entry_what}.frame {frame} lies outside the take range \
                     {}..={}",
                    frames.start, frames.end
                )));
            }
            if let Some(prev) = previous
                && frame <= prev
            {
                return Err(refuse(format!(
                    "{entry_what}.frame {frame} does not ascend past {prev}"
                )));
            }
            previous = Some(frame);
            match entry.get("artifact").and_then(Value::as_str) {
                Some(text) if is_sha256_hex(text) => {}
                _ => {
                    return Err(refuse(format!(
                        "{entry_what}.artifact must be the 64-hex content hash of a \
                         v1 gp_strokes artifact (DESIGN-ANIM §1.3)"
                    )));
                }
            }
        }
        total_refs = total_refs
            .checked_add(track_frames.len())
            .ok_or_else(|| refuse("take GP reference count overflowed".to_string()))?;
        if total_refs > MAX_GP_REFS_TOTAL {
            return Err(refuse(format!(
                "take carries more than {MAX_GP_REFS_TOTAL} GP frame references \
                 (refused, not truncated)"
            )));
        }
    }
    let baked = match object.get("bake") {
        None | Some(Value::Null) => false,
        Some(bake) => {
            check_bake(bake, &frames, &addresses)?;
            true
        }
    };
    let claimed = check_sha256_field(object, "take")?;
    check_content_hash(envelope, &claimed, "take")?;
    Ok(TakeInfo {
        id,
        sha256: claimed,
        channels: channels.len(),
        keys: total_keys,
        gp_tracks: gp_tracks.len(),
        gp_refs: total_refs,
        baked,
    })
}

fn check_bake(bake: &Value, frames: &Frames, addresses: &HashSet<String>) -> Result<(), String> {
    let Some(bake) = bake.as_object() else {
        return Err(refuse("take.bake must be null or an object".to_string()));
    };
    check_keys(
        bake,
        &[
            "system",
            "blender",
            "frames",
            "settings",
            "settings_sha256",
            "channels",
            "evidence",
        ],
        "take.bake",
    )?;
    required_string(bake, "system", "take.bake")?;
    required_string(bake, "blender", "take.bake")?;
    required_string(bake, "evidence", "take.bake")?;
    let bake_frames = check_frames(
        bake.get("frames").ok_or("take.bake.frames is required")?,
        "take.bake.frames",
    )?;
    if bake_frames.start != frames.start
        || bake_frames.end != frames.end
        || bake_frames.fps_num != frames.fps_num
        || bake_frames.fps_base != frames.fps_base
    {
        return Err(refuse(
            "take.bake.frames must equal the take's frame block (a bake is of the \
             take's range at the take's rate, DESIGN-ANIM §4.2)"
                .to_string(),
        ));
    }
    let Some(settings) = bake.get("settings") else {
        return Err(refuse("take.bake.settings is required".to_string()));
    };
    if !settings.is_object() {
        return Err(refuse(
            "take.bake.settings must be an object (the sim's full evaluated \
             property set, transcribed)"
                .to_string(),
        ));
    }
    let settings_hash = hex(&Sha256::digest(canonical_bytes(settings)));
    match bake.get("settings_sha256").and_then(Value::as_str) {
        Some(text) if text == settings_hash => {}
        _ => {
            return Err(refuse(format!(
                "take.bake.settings_sha256 does not match the settings content hash \
                 (computed {settings_hash}); a bake whose settings are not recorded \
                 exactly is a rumour (DESIGN-ANIM §4.2)"
            )));
        }
    }
    let Some(baked_channels) = bake.get("channels").and_then(Value::as_array) else {
        return Err(refuse(
            "take.bake.channels must be an array of channel addresses".to_string(),
        ));
    };
    if baked_channels.is_empty() {
        return Err(refuse(
            "take.bake.channels must name at least one baked channel".to_string(),
        ));
    }
    for entry in baked_channels {
        let Some(address) = entry.as_str() else {
            return Err(refuse(
                "take.bake.channels entries must be channel address strings".to_string(),
            ));
        };
        if !addresses.contains(address) {
            return Err(refuse(format!(
                "take.bake.channels names {address:?}, which is not a channel of \
                 this take"
            )));
        }
    }
    Ok(())
}

/// Validates one pose envelope end to end (DESIGN-ANIM §1.4):
/// values only, one frame, the take's channel grammar, and
/// the insert rule — BEZIER inserts are admissible only when
/// every channel carries handles, because a pose is a
/// position and its easing belongs to the curve work.
pub fn validate_pose(envelope: &Value) -> Result<PoseInfo, String> {
    if let Some(excluded) = find_excluded(envelope, false) {
        return Err(refuse(format!(
            "pose carries excluded construct {excluded:?} (DESIGN-ANIM §3)"
        )));
    }
    let Some(object) = envelope.as_object() else {
        return Err(refuse("pose must be a JSON object".to_string()));
    };
    check_keys(
        object,
        &[
            "schema",
            "id",
            "created_by",
            "target",
            "frame",
            "channels",
            "insert",
            "sha256",
        ],
        "pose",
    )?;
    if object.get("schema").and_then(Value::as_str) != Some(POSE_SCHEMA) {
        return Err(refuse(format!("pose.schema must be {POSE_SCHEMA:?}")));
    }
    let id = required_id(object, "pose")?;
    check_created_by(object, "pose")?;
    check_scene_sha(object, "pose")?;
    let Some(target) = object.get("target").and_then(Value::as_object) else {
        return Err(refuse("pose.target must be an object".to_string()));
    };
    check_keys(target, &["scene_sha256"], "pose.target")?;
    if object.get("frame").and_then(Value::as_u64).is_none() {
        return Err(refuse(
            "pose.frame must be a non-negative integer".to_string(),
        ));
    }
    let Some(insert) = object.get("insert").and_then(Value::as_object) else {
        return Err(refuse("pose.insert must be an object".to_string()));
    };
    check_keys(insert, &["interp"], "pose.insert")?;
    let insert_interp = match insert.get("interp").and_then(Value::as_str) {
        Some(text) if ["CONSTANT", "LINEAR", "BEZIER"].contains(&text) => text,
        _ => {
            return Err(refuse(
                "pose.insert.interp must be CONSTANT | LINEAR | BEZIER".to_string(),
            ));
        }
    };
    let Some(channels) = object.get("channels").and_then(Value::as_array) else {
        return Err(refuse("pose.channels must be an array".to_string()));
    };
    if channels.is_empty() {
        return Err(refuse(
            "pose.channels must not be empty (a pose with no values poses nothing)".to_string(),
        ));
    }
    if channels.len() > MAX_POSE_CHANNELS {
        return Err(refuse(format!(
            "pose carries {} channels; the bound is {MAX_POSE_CHANNELS} \
             (refused, not truncated)",
            channels.len()
        )));
    }
    let mut addresses: HashSet<String> = HashSet::new();
    for (index, channel) in channels.iter().enumerate() {
        let what = format!("pose.channels[{index}]");
        let Some(channel) = channel.as_object() else {
            return Err(refuse(format!("{what} must be an object")));
        };
        let head = check_channel_head(channel, &what, false)?;
        if !addresses.insert(head.address.clone()) {
            return Err(refuse(format!(
                "pose carries channel {} twice",
                head.address
            )));
        }
        if channel
            .get("value")
            .and_then(Value::as_str)
            .and_then(decimal6)
            .is_none()
        {
            return Err(refuse(format!(
                "{what}.value must be a 6-decimal string (D2)"
            )));
        }
        let handle_left = check_handle_pair(channel, "handle_left", &what)?;
        let handle_right = check_handle_pair(channel, "handle_right", &what)?;
        let handle_left_type = check_handle_type(channel, "handle_left_type", &what)?;
        let handle_right_type = check_handle_type(channel, "handle_right_type", &what)?;
        let has_handles = handle_left.is_some()
            && handle_right.is_some()
            && handle_left_type.is_some()
            && handle_right_type.is_some();
        if insert_interp == "BEZIER" && !has_handles {
            return Err(refuse(format!(
                "{what} carries no handles, but pose.insert.interp is BEZIER; a \
                 BEZIER insert is admissible only if the pose carries handles per \
                 channel (DESIGN-ANIM §1.4)"
            )));
        }
        if insert_interp != "BEZIER"
            && (handle_left.is_some()
                || handle_right.is_some()
                || handle_left_type.is_some()
                || handle_right_type.is_some())
        {
            return Err(refuse(format!(
                "{what} carries handle data, but pose.insert.interp is {insert_interp}"
            )));
        }
    }
    let claimed = check_sha256_field(object, "pose")?;
    check_content_hash(envelope, &claimed, "pose")?;
    Ok(PoseInfo {
        id,
        sha256: claimed,
        channels: channels.len(),
    })
}

/// The target summary of one channel for the export form:
/// which rig bone, shape-key block, or object a channel
/// animates, derived from its address (DESIGN-ANIM §5 — the
/// export renames nothing; it flattens).
fn export_target(channel: &Map<String, Value>) -> Value {
    let id = channel.get("id").cloned().unwrap_or(Value::Null);
    let path = channel
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (kind, name) = if let Some(rest) = path.strip_prefix("pose.bones[\"") {
        ("bone", rest.split_once("\"]").map(|(n, _)| n.to_string()))
    } else if let Some(rest) = path.strip_prefix("key_blocks[\"") {
        (
            "shape_key",
            rest.split_once("\"]").map(|(n, _)| n.to_string()),
        )
    } else if channel
        .get("id")
        .and_then(|i| i.get("type"))
        .and_then(Value::as_str)
        == Some("GREASE_PENCIL")
    {
        ("grease_pencil", None)
    } else {
        ("object", None)
    };
    let name = name.unwrap_or_else(|| {
        id.get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    });
    serde_json::json!({
        "kind": kind,
        "name": name,
        "id": id,
        "slot": channel.get("slot").cloned().unwrap_or(Value::Null),
    })
}

/// Transforms a take into the D-1397 timeline compiler's
/// input form (DESIGN-ANIM §5). Lossless or refused: the take
/// is validated first, and every key — handles, handle types,
/// and easing parameters included — is carried verbatim,
/// because a compiler that cannot reproduce a curve's handles
/// cannot reproduce the curve. The export stamps its own
/// content hash; the source take's hash rides as provenance.
pub fn export_take(envelope: &Value) -> Result<Value, String> {
    let info = validate_take(envelope)?;
    let object = envelope.as_object().expect("validated object");
    let mut channels_out = Vec::new();
    for channel in object
        .get("channels")
        .and_then(Value::as_array)
        .expect("validated channels")
    {
        let channel = channel.as_object().expect("validated channel");
        channels_out.push(serde_json::json!({
            "target": export_target(channel),
            "path": channel.get("path").cloned().unwrap_or(Value::Null),
            "index": channel.get("index").cloned().unwrap_or(Value::Null),
            "extrapolation": channel.get("extrapolation").cloned().unwrap_or(Value::Null),
            "keys": channel.get("keys").cloned().unwrap_or(Value::Null),
        }));
    }
    let mut export = serde_json::json!({
        "schema": EXPORT_SCHEMA,
        "take": {
            "id": info.id,
            "sha256": info.sha256,
            "scene_sha256": object
                .get("target")
                .and_then(|t| t.get("scene_sha256"))
                .cloned()
                .unwrap_or(Value::Null),
            "rig": object
                .get("target")
                .and_then(|t| t.get("rig"))
                .cloned()
                .unwrap_or(Value::Null),
        },
        "frames": object.get("frames").cloned().unwrap_or(Value::Null),
        "channels": channels_out,
        "gp_tracks": object.get("gp_tracks").cloned().unwrap_or(Value::Null),
        "bake": object.get("bake").cloned().unwrap_or(Value::Null),
    });
    let hash = content_hash(&export).expect("export is an object");
    export["sha256"] = Value::String(hash);
    Ok(export)
}

/// The action digest (DESIGN-ANIM §6.1): SHA-256 over
/// canonical lines per channel — address and extrapolation,
/// then per key in frame order every field evaluation reads,
/// in the artifact's own 6-decimal strings. This is the
/// instrument the twin-apply and round-trip gates are stated
/// in; the addon computes the identical digest over a
/// captured take, so broker and provider agree on what "the
/// same motion" means byte for byte.
pub fn action_digest(envelope: &Value) -> Result<String, String> {
    validate_take(envelope)?;
    let object = envelope.as_object().expect("validated object");
    let mut lines: Vec<String> = Vec::new();
    for channel in object
        .get("channels")
        .and_then(Value::as_array)
        .expect("validated channels")
    {
        let channel = channel.as_object().expect("validated channel");
        let id = channel.get("id").expect("validated id");
        let slot = channel.get("slot").and_then(Value::as_str).unwrap_or("");
        lines.push(format!(
            "C|{}|{}|{}|{}|{}|{}",
            id.get("type").and_then(Value::as_str).unwrap_or(""),
            id.get("name").and_then(Value::as_str).unwrap_or(""),
            slot,
            channel.get("path").and_then(Value::as_str).unwrap_or(""),
            channel.get("index").and_then(Value::as_u64).unwrap_or(0),
            channel
                .get("extrapolation")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ));
        for key in channel
            .get("keys")
            .and_then(Value::as_array)
            .expect("validated keys")
        {
            let key = key.as_object().expect("validated key");
            let text = |field: &str| key.get(field).and_then(Value::as_str).unwrap_or("");
            let pair = |field: &str| match key.get(field) {
                Some(Value::Array(parts)) if parts.len() == 2 => format!(
                    "{},{}",
                    parts[0].as_str().unwrap_or(""),
                    parts[1].as_str().unwrap_or("")
                ),
                _ => String::new(),
            };
            lines.push(format!(
                "K|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                text("frame"),
                text("value"),
                text("interp"),
                text("easing"),
                pair("handle_left"),
                pair("handle_right"),
                text("handle_left_type"),
                text("handle_right_type"),
                text("back"),
                text("amplitude"),
                text("period"),
            ));
        }
    }
    let mut bytes = Vec::new();
    for line in &lines {
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    Ok(hex(&Sha256::digest(&bytes)))
}

/// What validation learned about a rigbuild.
#[derive(Clone, Debug)]
pub struct RigbuildInfo {
    pub id: String,
    pub sha256: String,
    pub bones: usize,
    pub constraints: usize,
    pub weight_groups: usize,
    pub vertices: usize,
}

/// Validates one rigbuild envelope end to end: a declarative
/// rig-construction document (bones, pose-bone constraints,
/// vertex-group weights — all as data) bound to one scene by
/// hash. Existence of the named armature, bones, and objects
/// is the provider's check; the broker checks the document.
pub fn validate_rigbuild(envelope: &Value) -> Result<RigbuildInfo, String> {
    let Some(object) = envelope.as_object() else {
        return Err(refuse("rigbuild must be a JSON object".to_string()));
    };
    if let Some(excluded) = find_excluded(envelope, false) {
        return Err(refuse(format!(
            "rigbuild carries excluded construct {excluded:?} (DESIGN-ANIM §3)"
        )));
    }
    check_keys(
        object,
        &[
            "schema",
            "id",
            "created_by",
            "target",
            "bones",
            "constraints",
            "weights",
            "sha256",
        ],
        "rigbuild",
    )?;
    if object.get("schema").and_then(Value::as_str) != Some(RIGBUILD_SCHEMA) {
        return Err(refuse(format!(
            "rigbuild.schema must be {RIGBUILD_SCHEMA:?}"
        )));
    }
    let id = required_id(object, "rigbuild")?;
    check_created_by(object, "rigbuild")?;
    let Some(target) = object.get("target").and_then(Value::as_object) else {
        return Err(refuse("rigbuild.target must be an object".to_string()));
    };
    check_keys(target, &["scene_sha256", "armature"], "rigbuild.target")?;
    let scene = target
        .get("scene_sha256")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !is_sha256_hex(scene) {
        return Err(refuse(
            "rigbuild.target.scene_sha256 must be 64 lowercase hex characters \
             (the scene-hash binding, DESIGN-ANIM §1.1)"
                .to_string(),
        ));
    }
    required_string(target, "armature", "rigbuild.target")?;
    let bones = object
        .get("bones")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("rigbuild.bones must be an array".to_string()))?;
    if bones.len() > MAX_RIG_BONES {
        return Err(refuse(format!(
            "rigbuild carries {} bones; the bound is {MAX_RIG_BONES} (refused, not truncated)",
            bones.len()
        )));
    }
    let mut names: Vec<&str> = Vec::new();
    for (index, bone) in bones.iter().enumerate() {
        let what = format!("rigbuild.bones[{index}]");
        let Some(bone) = bone.as_object() else {
            return Err(refuse(format!("{what} must be an object")));
        };
        check_keys(
            bone,
            &["name", "parent", "head", "tail", "roll", "deform"],
            &what,
        )?;
        let name = required_string(bone, "name", &what)?;
        if names.contains(&name) {
            return Err(refuse(format!("rigbuild carries bone {name:?} twice")));
        }
        names.push(name);
        match bone.get("parent") {
            Some(Value::Null) | None => {}
            Some(Value::String(_)) => {}
            _ => return Err(refuse(format!("{what}.parent must be a string or null"))),
        }
        for axis in ["head", "tail"] {
            let vec = bone.get(axis).and_then(Value::as_array);
            let ok = matches!(vec, Some(items) if items.len() == 3
                && items.iter().all(|c| c.as_str().is_some_and(is_decimal6)));
            if !ok {
                return Err(refuse(format!(
                    "{what}.{axis} must be three 6-decimal strings (D2)"
                )));
            }
        }
        if !bone
            .get("roll")
            .and_then(Value::as_str)
            .is_some_and(is_decimal6)
        {
            return Err(refuse(format!(
                "{what}.roll must be a 6-decimal string (D2)"
            )));
        }
        if !bone.get("deform").is_some_and(Value::is_boolean) {
            return Err(refuse(format!("{what}.deform must be a boolean")));
        }
    }
    let constraints = object
        .get("constraints")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("rigbuild.constraints must be an array".to_string()))?;
    if constraints.len() > MAX_RIG_CONSTRAINTS {
        return Err(refuse(format!(
            "rigbuild carries {} constraints; the bound is {MAX_RIG_CONSTRAINTS}",
            constraints.len()
        )));
    }
    for (index, con) in constraints.iter().enumerate() {
        let what = format!("rigbuild.constraints[{index}]");
        let Some(con) = con.as_object() else {
            return Err(refuse(format!("{what} must be an object")));
        };
        check_keys(
            con,
            &[
                "bone",
                "type",
                "name",
                "target",
                "subtarget",
                "chain_count",
                "influence",
            ],
            &what,
        )?;
        required_string(con, "bone", &what)?;
        if !con
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| RIG_CONSTRAINT_TYPES.contains(&t))
        {
            return Err(refuse(format!(
                "{what}.type must be one of {RIG_CONSTRAINT_TYPES:?}"
            )));
        }
        match con.get("name") {
            Some(Value::Null) | None => {}
            Some(Value::String(_)) => {}
            _ => return Err(refuse(format!("{what}.name must be a string or null"))),
        }
        match con.get("target") {
            Some(Value::Null) | None => {}
            Some(Value::Object(tgt)) => {
                check_keys(tgt, &["type", "name"], &format!("{what}.target"))?;
                if tgt.get("type").and_then(Value::as_str) != Some("OBJECT") {
                    return Err(refuse(format!(
                        "{what}.target must name an object (type OBJECT)"
                    )));
                }
                required_string(tgt, "name", &format!("{what}.target"))?;
            }
            _ => return Err(refuse(format!("{what}.target must be an object or null"))),
        }
        if !con.get("subtarget").is_some_and(Value::is_string) {
            return Err(refuse(format!("{what}.subtarget must be a string")));
        }
        match con.get("chain_count") {
            Some(Value::Null) | None => {}
            Some(value) => {
                let ok = value
                    .as_i64()
                    .is_some_and(|n| (0..=32).contains(&n) && value.is_i64());
                if !ok {
                    return Err(refuse(format!(
                        "{what}.chain_count must be null or an integer in [0, 32]"
                    )));
                }
            }
        }
        if !con
            .get("influence")
            .and_then(Value::as_str)
            .is_some_and(is_decimal6)
        {
            return Err(refuse(format!(
                "{what}.influence must be a 6-decimal string (D2)"
            )));
        }
    }
    let weights = object
        .get("weights")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("rigbuild.weights must be an array".to_string()))?;
    if weights.len() > MAX_RIG_WEIGHT_GROUPS {
        return Err(refuse(format!(
            "rigbuild carries {} weight groups; the bound is {MAX_RIG_WEIGHT_GROUPS}",
            weights.len()
        )));
    }
    let mut total_vertices: usize = 0;
    for (index, group) in weights.iter().enumerate() {
        let what = format!("rigbuild.weights[{index}]");
        let Some(group) = group.as_object() else {
            return Err(refuse(format!("{what} must be an object")));
        };
        check_keys(group, &["mesh", "group", "vertices", "weight"], &what)?;
        required_string(group, "mesh", &what)?;
        required_string(group, "group", &what)?;
        let Some(vertices) = group.get("vertices").and_then(Value::as_array) else {
            return Err(refuse(format!(
                "{what}.vertices must be an array of non-negative integers"
            )));
        };
        let mut seen: Vec<u64> = Vec::new();
        for vertex in vertices {
            let Some(v) = vertex.as_u64() else {
                return Err(refuse(format!(
                    "{what}.vertices must be an array of non-negative integers"
                )));
            };
            if seen.contains(&v) {
                return Err(refuse(format!("{what}.vertices carries a vertex twice")));
            }
            seen.push(v);
        }
        total_vertices += vertices.len();
        let weight = group
            .get("weight")
            .and_then(Value::as_str)
            .and_then(decimal6);
        match weight {
            Some(w) if (0.0..=1.0).contains(&w) => {}
            _ => {
                return Err(refuse(format!(
                    "{what}.weight must be a 6-decimal string in [0, 1] (D2)"
                )));
            }
        }
    }
    if total_vertices > MAX_RIG_VERTICES {
        return Err(refuse(format!(
            "rigbuild weights {total_vertices} vertices in total; the bound is {MAX_RIG_VERTICES}"
        )));
    }
    if bones.is_empty() && constraints.is_empty() && weights.is_empty() {
        return Err(refuse(
            "rigbuild carries no bones, constraints, or weights; an empty build is refused"
                .to_string(),
        ));
    }
    let sha256 = check_sha256_field(object, "rigbuild")?;
    check_content_hash(envelope, &sha256, "rigbuild")?;
    Ok(RigbuildInfo {
        id,
        sha256,
        bones: bones.len(),
        constraints: constraints.len(),
        weight_groups: weights.len(),
        vertices: total_vertices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCENE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn bezier_key(frame: &str, value: &str) -> Value {
        json!({
            "frame": frame, "value": value, "interp": "BEZIER", "easing": null,
            "handle_left": ["0.000000", "0.000000"],
            "handle_right": ["2.000000", "1.000000"],
            "handle_left_type": "AUTO_CLAMPED", "handle_right_type": "AUTO_CLAMPED",
            "back": null, "amplitude": null, "period": null
        })
    }

    /// A minimal valid take: one bezier bone channel, one
    /// BACK-eased shape-key channel, one held GP reference.
    fn valid_take() -> Value {
        let mut take = json!({
            "schema": TAKE_SCHEMA,
            "id": "prima-blink-test",
            "created_by": "test",
            "target": {"scene_sha256": SCENE, "rig": "PrimaRig"},
            "frames": {"start": 1, "end": 24, "fps_num": 24, "fps_base": "1.000000"},
            "channels": [
                {
                    "id": {"type": "OBJECT", "name": "PrimaRig"},
                    "slot": null,
                    "path": "pose.bones[\"Head\"].rotation_quaternion",
                    "index": 0,
                    "extrapolation": "CONSTANT",
                    "keys": [bezier_key("1.000000", "1.000000"),
                             bezier_key("24.000000", "0.980000")]
                },
                {
                    "id": {"type": "KEY", "name": "PrimaFace"},
                    "slot": null,
                    "path": "key_blocks[\"Fac_Blink_L\"].value",
                    "index": 0,
                    "extrapolation": "CONSTANT",
                    "keys": [{
                        "frame": "6.000000", "value": "0.000000",
                        "interp": "BACK", "easing": "EASE_OUT",
                        "handle_left": null, "handle_right": null,
                        "handle_left_type": null, "handle_right_type": null,
                        "back": "1.701580", "amplitude": null, "period": null
                    }]
                }
            ],
            "gp_tracks": [{
                "object": "Prima_Locks", "layer": "Sketch",
                "frames": [{"frame": 1, "artifact": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
            }],
            "bake": null
        });
        let hash = content_hash(&take).expect("hash");
        take["sha256"] = json!(hash);
        take
    }

    fn restamp(take: &mut Value) {
        take.as_object_mut().unwrap().remove("sha256");
        let hash = content_hash(take).expect("hash");
        take["sha256"] = json!(hash);
    }

    #[test]
    fn valid_take_validates() {
        let info = validate_take(&valid_take()).expect("valid take");
        assert_eq!(info.channels, 2);
        assert_eq!(info.keys, 3);
        assert_eq!(info.gp_refs, 1);
        assert!(!info.baked);
    }

    #[test]
    fn tampered_hash_is_refused() {
        let mut take = valid_take();
        take["id"] = json!("prima-blink-test-2");
        let error = validate_take(&take).expect_err("tamper must refuse");
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn excluded_constructs_are_refused_by_name() {
        for (field, value) in [
            ("modifiers", json!(["CYCLES"])),
            ("drivers", json!([])),
            ("nla", json!([])),
        ] {
            let mut take = valid_take();
            take["channels"][0][field] = value;
            restamp(&mut take);
            let error = validate_take(&take).expect_err("excluded must refuse");
            assert!(error.contains("excluded construct"), "{field}: {error}");
        }
    }

    #[test]
    fn bezier_key_without_handles_is_refused() {
        let mut take = valid_take();
        take["channels"][0]["keys"][0]["handle_left"] = Value::Null;
        restamp(&mut take);
        let error = validate_take(&take).expect_err("handle-less bezier must refuse");
        assert!(error.contains("BEZIER"), "{error}");
    }

    #[test]
    fn back_key_without_back_param_is_refused() {
        let mut take = valid_take();
        take["channels"][1]["keys"][0]["back"] = Value::Null;
        restamp(&mut take);
        let error = validate_take(&take).expect_err("BACK without back must refuse");
        assert!(error.contains("back"), "{error}");
    }

    #[test]
    fn key_outside_range_and_duplicate_channel_refuse() {
        let mut take = valid_take();
        take["channels"][0]["keys"][1]["frame"] = json!("30.000000");
        restamp(&mut take);
        let error = validate_take(&take).expect_err("out-of-range key must refuse");
        assert!(error.contains("outside the take range"), "{error}");

        let mut take = valid_take();
        let channel = take["channels"][0].clone();
        take["channels"].as_array_mut().unwrap().push(channel);
        restamp(&mut take);
        let error = validate_take(&take).expect_err("duplicate channel must refuse");
        assert!(error.contains("twice"), "{error}");
    }

    #[test]
    fn over_bounds_take_is_refused_not_truncated() {
        let mut take = valid_take();
        let channel = take["channels"][0].clone();
        let mut channels = Vec::new();
        for n in 0..=MAX_CHANNELS {
            let mut c = channel.clone();
            c["path"] = json!(format!("pose.bones[\"Bone{n}\"].rotation_quaternion"));
            channels.push(c);
        }
        take["channels"] = Value::Array(channels);
        restamp(&mut take);
        let error = validate_take(&take).expect_err("over bounds must refuse");
        assert!(error.contains("bound is"), "{error}");
    }

    #[test]
    fn export_is_lossless_and_stamped() {
        let take = valid_take();
        let export = export_take(&take).expect("export");
        assert_eq!(export["schema"], json!(EXPORT_SCHEMA));
        assert_eq!(export["take"]["sha256"], take["sha256"]);
        let keys = export["channels"][0]["keys"].as_array().unwrap();
        assert_eq!(keys[0]["handle_left"], json!(["0.000000", "0.000000"]));
        assert_eq!(export["channels"][0]["target"]["kind"], json!("bone"));
        assert_eq!(export["channels"][0]["target"]["name"], json!("Head"));
        assert_eq!(export["channels"][1]["target"]["kind"], json!("shape_key"));
        // The export's own hash verifies under the same rule.
        let claimed = export["sha256"].as_str().unwrap().to_string();
        assert_eq!(content_hash(&export).unwrap(), claimed);
    }

    #[test]
    fn action_digest_is_stable_and_sensitive() {
        let take = valid_take();
        let digest = action_digest(&take).expect("digest");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, action_digest(&take).expect("digest again"));
        let mut other = valid_take();
        other["channels"][0]["keys"][0]["value"] = json!("0.500000");
        restamp(&mut other);
        assert_ne!(digest, action_digest(&other).expect("other digest"));
    }

    fn valid_pose() -> Value {
        let mut pose = json!({
            "schema": POSE_SCHEMA,
            "id": "prima-pose-test",
            "created_by": "test",
            "target": {"scene_sha256": SCENE},
            "frame": 12,
            "channels": [{
                "id": {"type": "OBJECT", "name": "PrimaRig"},
                "slot": null,
                "path": "pose.bones[\"Head\"].rotation_quaternion",
                "index": 0,
                "value": "0.990000"
            }],
            "insert": {"interp": "LINEAR"}
        });
        let hash = content_hash(&pose).expect("hash");
        pose["sha256"] = json!(hash);
        pose
    }

    #[test]
    fn valid_pose_validates() {
        let info = validate_pose(&valid_pose()).expect("valid pose");
        assert_eq!(info.channels, 1);
    }

    #[test]
    fn bezier_pose_without_handles_is_refused() {
        let mut pose = valid_pose();
        pose["insert"]["interp"] = json!("BEZIER");
        pose.as_object_mut().unwrap().remove("sha256");
        let hash = content_hash(&pose).expect("hash");
        pose["sha256"] = json!(hash);
        let error = validate_pose(&pose).expect_err("BEZIER pose without handles");
        assert!(error.contains("BEZIER"), "{error}");
    }

    #[test]
    fn baked_take_validates_and_bad_bake_refuses() {
        let mut take = valid_take();
        let settings = json!({"quality": 5, "solver": "cloth"});
        let settings_hash = hex(&Sha256::digest(canonical_bytes(&settings)));
        take["bake"] = json!({
            "system": "HairCloth",
            "blender": "5.3.0",
            "frames": {"start": 1, "end": 24, "fps_num": 24, "fps_base": "1.000000"},
            "settings": settings,
            "settings_sha256": settings_hash,
            "channels": ["OBJECT:PrimaRig|pose.bones[\"Head\"].rotation_quaternion|0"],
            "evidence": "bake-run-1"
        });
        restamp(&mut take);
        let info = validate_take(&take).expect("baked take");
        assert!(info.baked);
        // A bake naming a channel the take does not carry refuses.
        take["bake"]["channels"] = json!(["OBJECT:Nope|location|0"]);
        restamp(&mut take);
        let error = validate_take(&take).expect_err("phantom baked channel");
        assert!(error.contains("not a channel"), "{error}");
    }
}
