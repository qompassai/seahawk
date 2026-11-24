//! Stroke artifacts (DESIGN §2): the frozen, shippable drawing
//! unit for the Blender stroke-data provider.
//!
//! An artifact is canonical JSON (sorted keys, no insignificant
//! whitespace) whose numeric leaves are 6-decimal strings (the
//! estate `%.6f` digest convention, D2). Its embedded `sha256`
//! is computed over the canonical bytes of everything else in
//! the envelope, so the op log's args digest transitively pins
//! the exact stroke data a call applied (DESIGN §5) without
//! logging raw values.
//!
//! This module is the broker-side validator: schema, Tiger-Style
//! bounds, the determinism exclusion set (DESIGN §3), and hash
//! recomputation. Write-class blender ops validate here before
//! the downstream is contacted; `blender.artifact_validate`
//! serves this module directly and never touches the scene.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "seahawk.stroke/v1";

/// Hard bounds (DESIGN §2.2): an artifact outside them is
/// refused, never truncated.
pub const MAX_STROKES: usize = 4096;
pub const MAX_POINTS_PER_STROKE: usize = 8192;
pub const MAX_POINTS_TOTAL: usize = 2_000_000;
pub const MAX_ID_CHARS: usize = 128;
pub const MAX_NAME_CHARS: usize = 256;

/// The determinism exclusion set (DESIGN §3), enforced by name:
/// any of these keys appearing anywhere in an artifact refuses
/// it. These are Blender's interactive-engine features — jitter,
/// dynamics, texture brushes, sculpt, physics — whose results
/// depend on timing, library state, or unseeded randomness and
/// so can never replay byte-identically.
pub const EXCLUDED_KEYS: [&str; 13] = [
    "airbrush",
    "dynamics",
    "dyntopo",
    "jitter",
    "physics",
    "random",
    "random_falloff",
    "random_rotation",
    "sculpt",
    "simulation",
    "stroke_method",
    "texture",
    "use_jitter",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    PaintBatch,
    GpStrokes,
    FlowCurves,
}

impl ArtifactKind {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "paint_batch" => Some(Self::PaintBatch),
            "gp_strokes" => Some(Self::GpStrokes),
            "flow_curves" => Some(Self::FlowCurves),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PaintBatch => "paint_batch",
            Self::GpStrokes => "gp_strokes",
            Self::FlowCurves => "flow_curves",
        }
    }

    /// Coordinate dimension per point for this kind (DESIGN
    /// §2.2): paint lives in UV space, GP and flow curves in
    /// object-local metres.
    pub fn point_dim(&self) -> usize {
        match self {
            Self::PaintBatch => 2,
            Self::GpStrokes | Self::FlowCurves => 3,
        }
    }
}

/// What validation learned about an artifact.
#[derive(Clone, Debug)]
pub struct ArtifactInfo {
    pub kind: ArtifactKind,
    pub id: String,
    pub sha256: String,
    pub strokes: usize,
    pub points: usize,
}

/// Canonical bytes of a JSON value, per DESIGN §2: object keys
/// sorted, no insignificant whitespace, and every JSON number
/// rendered as a 6-decimal string (so authoring and replay
/// machines format identically). Strings pass through as JSON
/// strings; booleans and null are literals.
pub fn canonical_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            let rendered = format!("{:.6}", number.as_f64().unwrap_or(0.0));
            write_json_string(&rendered, out);
        }
        Value::String(text) => write_json_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(key, out);
                out.push(b':');
                write_canonical(&map[*key], out);
            }
            out.push(b'}');
        }
    }
}

fn write_json_string(text: &str, out: &mut Vec<u8>) {
    // serde_json's string rendering is the estate's canonical
    // escaping (control characters escaped, UTF-8 passthrough).
    let rendered = serde_json::to_string(text).expect("string rendering cannot fail");
    out.extend_from_slice(rendered.as_bytes());
}

/// The content hash of an artifact envelope: SHA-256 over the
/// canonical bytes of the envelope with `sha256` removed.
pub fn content_hash(envelope: &Value) -> Option<String> {
    let object = envelope.as_object()?;
    let mut stripped = Map::with_capacity(object.len());
    for (key, value) in object {
        if key != "sha256" {
            stripped.insert(key.clone(), value.clone());
        }
    }
    let bytes = canonical_bytes(&Value::Object(stripped));
    Some(hex(&Sha256::digest(&bytes)))
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A 6-decimal string per D2: optional minus, digits, a point,
/// exactly six fractional digits.
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

fn refuse(message: String) -> String {
    message
}

/// Scans every object key in the value against the exclusion
/// set; returns the first excluded key found.
fn find_excluded(value: &Value) -> Option<&'static str> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if let Some(hit) = EXCLUDED_KEYS.iter().find(|ex| **ex == key.as_str()) {
                    return Some(hit);
                }
                if let Some(hit) = find_excluded(child) {
                    return Some(hit);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(find_excluded),
        _ => None,
    }
}

fn check_keys(object: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), String> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(refuse(format!(
                "{what} carries unknown key {key:?}; schema {SCHEMA} admits only {allowed:?}"
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

/// A colour: null (brush colour applies) or four components in
/// [0, 1], each a JSON number or a 6-decimal string.
fn check_colour(value: &Value, what: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let Some(parts) = value.as_array() else {
        return Err(refuse(format!("{what} must be null or [r, g, b, a]")));
    };
    if parts.len() != 4 {
        return Err(refuse(format!(
            "{what} must have exactly 4 components, got {}",
            parts.len()
        )));
    }
    for part in parts {
        let component = match part {
            Value::Number(number) => number.as_f64(),
            Value::String(text) => decimal6(text),
            _ => None,
        };
        match component {
            Some(c) if (0.0..=1.0).contains(&c) => {}
            _ => {
                return Err(refuse(format!(
                    "{what} components must be numbers or 6-decimal strings within 0.0..=1.0"
                )));
            }
        }
    }
    Ok(())
}

fn check_brush(brush: &Value) -> Result<(), String> {
    let Some(object) = brush.as_object() else {
        return Err(refuse("brush must be an object".to_string()));
    };
    check_keys(
        object,
        &[
            "colour",
            "radius_px",
            "falloff",
            "spacing",
            "blend",
            "opacity",
        ],
        "brush",
    )?;
    check_colour(
        object.get("colour").ok_or("brush.colour is required")?,
        "brush.colour",
    )?;
    match object.get("radius_px").and_then(Value::as_u64) {
        Some(radius) if (1..=512).contains(&radius) => {}
        _ => {
            return Err(refuse(
                "brush.radius_px must be an integer within 1..=512".to_string(),
            ));
        }
    }
    match object.get("falloff").and_then(Value::as_str) {
        Some("smooth") | Some("constant") => {}
        Some(other) => {
            return Err(refuse(format!(
                "brush.falloff {other:?} is not in the v1 brush model (smooth | constant); \
                 richer falloffs are excluded by the determinism policy (DESIGN §3)"
            )));
        }
        None => {
            return Err(refuse(
                "brush.falloff must be smooth | constant".to_string(),
            ));
        }
    }
    match object.get("blend").and_then(Value::as_str) {
        Some("mix") | Some("alpha_over") => {}
        Some(other) => {
            return Err(refuse(format!(
                "brush.blend {other:?} is not in the v1 brush model (mix | alpha_over); \
                 richer blends are excluded by the determinism policy (DESIGN §3)"
            )));
        }
        None => return Err(refuse("brush.blend must be mix | alpha_over".to_string())),
    }
    match object.get("spacing").and_then(Value::as_f64) {
        Some(spacing) if spacing > 0.0 && spacing <= 10.0 => {}
        _ => {
            return Err(refuse(
                "brush.spacing must be a number within (0, 10]".to_string(),
            ));
        }
    }
    match object.get("opacity").and_then(Value::as_f64) {
        Some(opacity) if (0.0..=1.0).contains(&opacity) => {}
        _ => {
            return Err(refuse(
                "brush.opacity must be a number within 0.0..=1.0".to_string(),
            ));
        }
    }
    Ok(())
}

fn check_target(kind: ArtifactKind, target: &Value) -> Result<(), String> {
    let Some(object) = target.as_object() else {
        return Err(refuse("target must be an object".to_string()));
    };
    match kind {
        ArtifactKind::PaintBatch => {
            check_keys(object, &["image"], "target")?;
            required_string(object, "image", "target")?;
        }
        ArtifactKind::GpStrokes => {
            check_keys(object, &["object", "layer", "frame"], "target")?;
            required_string(object, "object", "target")?;
            required_string(object, "layer", "target")?;
            match object.get("frame").and_then(Value::as_u64) {
                Some(_) => {}
                _ => {
                    return Err(refuse(
                        "target.frame must be a non-negative integer".to_string(),
                    ));
                }
            }
        }
        ArtifactKind::FlowCurves => {
            check_keys(object, &["region"], "target")?;
            required_string(object, "region", "target")?;
        }
    }
    Ok(())
}

/// Validates one artifact envelope end to end: exclusion scan,
/// schema shape, bounds, per-kind target and brush, and the
/// embedded content hash. The error names the failure (and, for
/// exclusions, the excluded feature) — the validator is the
/// enforcement of DESIGN §3, not a convention.
pub fn validate_artifact(envelope: &Value) -> Result<ArtifactInfo, String> {
    if let Some(excluded) = find_excluded(envelope) {
        return Err(refuse(format!(
            "artifact carries excluded feature {excluded:?}: Blender's interactive-engine \
             features are policy-excluded because they cannot replay byte-identically \
             (DESIGN §3)"
        )));
    }
    let Some(object) = envelope.as_object() else {
        return Err(refuse("artifact must be a JSON object".to_string()));
    };
    check_keys(
        object,
        &[
            "schema",
            "kind",
            "id",
            "created_by",
            "target",
            "brush",
            "strokes",
            "sha256",
        ],
        "artifact",
    )?;
    if object.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err(refuse(format!("artifact.schema must be {SCHEMA:?}")));
    }
    let Some(kind_text) = object.get("kind").and_then(Value::as_str) else {
        return Err(refuse("artifact.kind must be a string".to_string()));
    };
    let Some(kind) = ArtifactKind::parse(kind_text) else {
        return Err(refuse(format!(
            "artifact.kind {kind_text:?} is not paint_batch | gp_strokes | flow_curves"
        )));
    };
    let id = match object.get("id").and_then(Value::as_str) {
        Some(text) if !text.is_empty() && text.chars().count() <= MAX_ID_CHARS => text,
        _ => {
            return Err(refuse(format!(
                "artifact.id must be a non-empty string of at most {MAX_ID_CHARS} characters"
            )));
        }
    };
    if let Some(created_by) = object.get("created_by") {
        match created_by.as_str() {
            Some(text) if text.chars().count() <= MAX_NAME_CHARS => {}
            _ => {
                return Err(refuse(
                    "artifact.created_by must be a short string".to_string(),
                ));
            }
        }
    }
    let target = object.get("target").ok_or("artifact.target is required")?;
    check_target(kind, target)?;
    match (kind, object.get("brush")) {
        (ArtifactKind::PaintBatch, Some(brush)) => check_brush(brush)?,
        (ArtifactKind::PaintBatch, None) => {
            return Err(refuse(
                "paint_batch artifacts require a brush block (DESIGN §2.3)".to_string(),
            ));
        }
        (_, Some(_)) => {
            return Err(refuse(
                "brush belongs to paint_batch artifacts only (DESIGN §2.1)".to_string(),
            ));
        }
        (_, None) => {}
    }
    let Some(strokes) = object.get("strokes").and_then(Value::as_array) else {
        return Err(refuse("artifact.strokes must be an array".to_string()));
    };
    if strokes.len() > MAX_STROKES {
        return Err(refuse(format!(
            "artifact carries {} strokes; the bound is {MAX_STROKES} (refused, not truncated)",
            strokes.len()
        )));
    }
    let dim = kind.point_dim();
    let mut total_points: usize = 0;
    for (index, stroke) in strokes.iter().enumerate() {
        let what = format!("strokes[{index}]");
        let Some(stroke) = stroke.as_object() else {
            return Err(refuse(format!("{what} must be an object")));
        };
        check_keys(stroke, &["points", "colour", "seed"], &what)?;
        if let Some(colour) = stroke.get("colour") {
            check_colour(colour, &format!("{what}.colour"))?;
        }
        if let Some(seed) = stroke.get("seed")
            && seed.as_u64().is_none()
        {
            return Err(refuse(format!(
                "{what}.seed must be a non-negative integer (the only permitted source \
                 of per-stroke variation)"
            )));
        }
        let Some(points) = stroke.get("points").and_then(Value::as_array) else {
            return Err(refuse(format!("{what}.points must be an array")));
        };
        if points.is_empty() {
            return Err(refuse(format!("{what}.points must not be empty")));
        }
        if points.len() > MAX_POINTS_PER_STROKE {
            return Err(refuse(format!(
                "{what} carries {} points; the bound is {MAX_POINTS_PER_STROKE} \
                 (refused, not truncated)",
                points.len()
            )));
        }
        total_points += points.len();
        if total_points > MAX_POINTS_TOTAL {
            return Err(refuse(format!(
                "artifact carries more than {MAX_POINTS_TOTAL} points in total \
                 (refused, not truncated)"
            )));
        }
        for (point_index, point) in points.iter().enumerate() {
            let what = format!("strokes[{index}].points[{point_index}]");
            let Some(point) = point.as_object() else {
                return Err(refuse(format!("{what} must be an object")));
            };
            check_keys(point, &["p", "pressure", "radius"], &what)?;
            let Some(coords) = point.get("p").and_then(Value::as_array) else {
                return Err(refuse(format!("{what}.p must be an array")));
            };
            if coords.len() != dim {
                return Err(refuse(format!(
                    "{what}.p must have {dim} coordinates for kind {}",
                    kind.as_str()
                )));
            }
            for coord in coords {
                match coord.as_str().and_then(decimal6) {
                    Some(_) => {}
                    None => {
                        return Err(refuse(format!(
                            "{what}.p coordinates must be 6-decimal strings (D2)"
                        )));
                    }
                }
            }
            match point
                .get("pressure")
                .and_then(Value::as_str)
                .and_then(decimal6)
            {
                Some(pressure) if (0.0..=1.0).contains(&pressure) => {}
                _ => {
                    return Err(refuse(format!(
                        "{what}.pressure must be a 6-decimal string within 0.0..=1.0"
                    )));
                }
            }
            match point
                .get("radius")
                .and_then(Value::as_str)
                .and_then(decimal6)
            {
                Some(radius) if radius > 0.0 => {}
                _ => {
                    return Err(refuse(format!(
                        "{what}.radius must be a 6-decimal string greater than 0"
                    )));
                }
            }
        }
    }
    let Some(claimed) = object.get("sha256").and_then(Value::as_str) else {
        return Err(refuse(
            "artifact.sha256 is required (hex, over the canonical bytes)".to_string(),
        ));
    };
    if claimed.len() != 64
        || !claimed
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse(
            "artifact.sha256 must be 64 lowercase hex characters".to_string(),
        ));
    }
    let computed = content_hash(envelope).expect("envelope is an object");
    if computed != claimed {
        return Err(refuse(format!(
            "artifact.sha256 does not match the canonical content hash (claimed {claimed}, \
             computed {computed}); the artifact is refused, not repaired"
        )));
    }
    Ok(ArtifactInfo {
        kind,
        id: id.to_string(),
        sha256: claimed.to_string(),
        strokes: strokes.len(),
        points: total_points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a minimal valid paint artifact and stamps its
    /// hash the way an author would.
    fn paint_artifact() -> Value {
        let mut artifact = json!({
            "schema": SCHEMA,
            "kind": "paint_batch",
            "id": "blush-test",
            "created_by": "test",
            "target": {"image": "prima_skin"},
            "brush": {
                "colour": [0.9, 0.4, 0.4, 1.0],
                "radius_px": 24,
                "falloff": "smooth",
                "spacing": 0.25,
                "blend": "alpha_over",
                "opacity": 0.8
            },
            "strokes": [{
                "points": [
                    {"p": ["0.100000", "0.200000"], "pressure": "0.500000", "radius": "1.000000"},
                    {"p": ["0.300000", "0.200000"], "pressure": "1.000000", "radius": "1.000000"}
                ],
                "colour": null,
                "seed": 7
            }]
        });
        let hash = content_hash(&artifact).expect("hash");
        artifact["sha256"] = json!(hash);
        artifact
    }

    #[test]
    fn valid_paint_artifact_validates() {
        let info = validate_artifact(&paint_artifact()).expect("valid artifact");
        assert_eq!(info.kind, ArtifactKind::PaintBatch);
        assert_eq!(info.strokes, 1);
        assert_eq!(info.points, 2);
    }

    #[test]
    fn canonical_bytes_are_key_sorted_and_number_normalized() {
        let value = json!({"b": 1, "a": [0.5, "x"]});
        assert_eq!(
            canonical_bytes(&value),
            br#"{"a":["0.500000","x"],"b":"1.000000"}"#.to_vec()
        );
    }

    #[test]
    fn tampered_hash_is_refused() {
        let mut artifact = paint_artifact();
        artifact["id"] = json!("blush-test-2");
        let error = validate_artifact(&artifact).expect_err("tamper must refuse");
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn excluded_feature_is_refused_by_name() {
        let mut artifact = paint_artifact();
        artifact["brush"]["jitter"] = json!(0.5);
        // Re-stamp the hash so only the exclusion can refuse it.
        artifact.as_object_mut().unwrap().remove("sha256");
        let hash = content_hash(&artifact).expect("hash");
        artifact["sha256"] = json!(hash);
        let error = validate_artifact(&artifact).expect_err("jitter must refuse");
        assert!(error.contains("excluded feature \"jitter\""), "{error}");
    }

    #[test]
    fn over_bounds_artifact_is_refused_not_truncated() {
        let mut artifact = paint_artifact();
        let stroke = artifact["strokes"][0].clone();
        artifact["strokes"] = Value::Array(vec![stroke; MAX_STROKES + 1]);
        let error = validate_artifact(&artifact).expect_err("over bounds must refuse");
        assert!(error.contains("bound is"), "{error}");
    }

    #[test]
    fn bad_decimal_and_wrong_dim_refuse() {
        let mut artifact = paint_artifact();
        artifact["strokes"][0]["points"][0]["p"] = json!(["0.1", "0.200000"]);
        let error = validate_artifact(&artifact).expect_err("short decimal must refuse");
        assert!(error.contains("6-decimal"), "{error}");
        let mut artifact = paint_artifact();
        artifact["strokes"][0]["points"][0]["p"] = json!(["0.100000", "0.200000", "0.000000"]);
        let error = validate_artifact(&artifact).expect_err("3d paint point must refuse");
        assert!(error.contains("must have 2 coordinates"), "{error}");
    }

    #[test]
    fn gp_artifact_validates_with_3d_points_and_no_brush() {
        let mut artifact = json!({
            "schema": SCHEMA,
            "kind": "gp_strokes",
            "id": "lock-sketch",
            "target": {"object": "Prima_Locks", "layer": "Sketch", "frame": 1},
            "strokes": [{
                "points": [
                    {"p": ["0.100000", "0.200000", "1.400000"], "pressure": "0.500000", "radius": "0.010000"}
                ],
                "colour": [1.0, 0.5, 0.5, 1.0]
            }]
        });
        let hash = content_hash(&artifact).expect("hash");
        artifact["sha256"] = json!(hash);
        let info = validate_artifact(&artifact).expect("valid gp artifact");
        assert_eq!(info.kind, ArtifactKind::GpStrokes);
        // A brush on a GP artifact is a schema violation.
        artifact["brush"] = json!({"colour": [0.0, 0.0, 0.0, 1.0], "radius_px": 4,
            "falloff": "smooth", "spacing": 0.5, "blend": "mix", "opacity": 1.0});
        let hash = content_hash(&artifact).expect("hash");
        artifact["sha256"] = json!(hash);
        assert!(validate_artifact(&artifact).is_err());
    }
}
