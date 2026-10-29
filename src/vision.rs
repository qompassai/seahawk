//! The S5 vision-grounding layer: the broker learns to *see*
//! where it clicks and types.
//!
//! Three pieces, mirroring D-208:
//!
//! - **Observe with geometry.** A captured frame is stored in a
//!   bounded frame store under its SHA-256, together with the
//!   window rectangle and the display geometry (root dimensions,
//!   scale factor, virtual-vs-live flag) in force when it was
//!   taken. Coordinates are therefore always interpretable: a
//!   point is meaningless without the frame it was read from,
//!   so grounding references frames by digest, never by "the
//!   current screen".
//! - **A pluggable grounder.** The `Grounder` trait is the seam:
//!   given a frame and a natural-language target, return a point
//!   with a confidence. The broker is model-agnostic — one route
//!   ships against a local vision model served by Ollama on
//!   loopback HTTP (the same loopback-only discipline as the
//!   Epic downstream; no subprocess, no off-machine call). The
//!   second route is a protocol, not a model: the calling agent
//!   answers the broker's grounding ticket with its own
//!   coordinates (see `gui.ground` in server.rs). Grounding is
//!   perception only — it grants no permission; actuation still
//!   passes `decide()` exactly as in S4.
//! - **Verification.** Post-action checks (frame-region change,
//!   window-title content, focus ownership, visible text via the
//!   grounder) evaluated against a fresh capture. A check the
//!   configured route cannot evaluate refuses the call *before*
//!   acting: Seahawk never performs an "act-verified" call it
//!   cannot actually verify.

use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::time::Duration;

use base64::Engine as _;
use serde::Serialize;
use serde_json::{Value, json};

use crate::gui::{Frame, GuiError, GuiResult, WindowInfo};
use crate::model::GuiApp;
use crate::policy::codes;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Frames kept in the store; older captures evict FIFO. A frame
/// is at most gui::MAX_FRAME_PIXELS, so the store is bounded too.
pub const MAX_STORED_FRAMES: usize = 16;
/// Longest grounding target description, in characters.
pub const MAX_TARGET_CHARS: usize = 256;
/// Half-size (px) of the evidence crop cut around a grounded
/// point: 2 * EVIDENCE_CROP_HALF + 1 on a side, clipped to the
/// frame.
pub const EVIDENCE_CROP_HALF: i32 = 120;
/// Half-size (px) of the region compared by the `changed` check.
pub const DIFF_REGION_HALF: i32 = 120;
/// Per-channel absolute delta above which a pixel counts as
/// changed for the `changed` check.
pub const DIFF_PIXEL_THRESHOLD: u8 = 24;
/// Fraction of region pixels that must change for the `changed`
/// check to pass. Deliberately low: a menu opening or a tool
/// highlight flips far more than 1% of a 241x241 region; sensor
/// noise flips far less.
pub const DIFF_CHANGED_FRACTION: f64 = 0.01;
/// Bounded correction in `gui.act_verified`: the initial attempt
/// plus at most this many re-ground + retry cycles.
pub const MAX_VERIFY_RETRIES: u32 = 2;

// ---------------------------------------------------------------------------
// Display geometry
// ---------------------------------------------------------------------------

/// The display a frame was captured on, as observed at capture
/// time. `virtual_display` is the lab's core distinction: Seahawk
/// is only ever pointed at a virtual display (Xvfb) in the lab
/// pattern, and the flag says which kind of display produced the
/// frame so a consumer never has to guess.
#[derive(Clone, Debug, Serialize)]
pub struct DisplayGeometry {
    /// Display name (`$DISPLAY` value, e.g. ":98"), when known.
    pub display: Option<String>,
    /// Root window dimensions in pixels.
    pub root_width: u32,
    pub root_height: u32,
    /// Physical size reported by the server, when it reports one.
    pub width_mm: Option<u32>,
    pub height_mm: Option<u32>,
    /// Pixels per 96-dpi unit (1.0 = unscaled), derived from the
    /// physical size when reported; 1.0 otherwise.
    pub scale_factor: f64,
    /// True when the display is virtual (Xvfb-class: the RandR
    /// outputs are the Xvfb "screen" output). False means the
    /// geometry came from what presents as a live display.
    pub virtual_display: bool,
}

impl DisplayGeometry {
    pub fn to_json(&self) -> Value {
        json!({
            "display": self.display,
            "root_width": self.root_width,
            "root_height": self.root_height,
            "width_mm": self.width_mm,
            "height_mm": self.height_mm,
            "scale_factor": self.scale_factor,
            "virtual_display": self.virtual_display,
        })
    }
}

// ---------------------------------------------------------------------------
// Frame store
// ---------------------------------------------------------------------------

/// A captured frame plus everything needed to interpret points
/// read from it: which app, which window rectangle, which
/// display geometry.
#[derive(Clone, Debug)]
pub struct StoredFrame {
    pub frame: Frame,
    pub app: String,
    pub window: WindowInfo,
    pub geometry: DisplayGeometry,
}

/// Bounded store of captured frames, keyed by the frame's PNG
/// SHA-256. Grounding and verification reference frames through
/// this store, so a point is always tied to the exact pixels it
//  was read from.
#[derive(Debug, Default)]
pub struct FrameStore {
    frames: HashMap<String, StoredFrame>,
    order: VecDeque<String>,
}

impl FrameStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a frame; returns its digest (the reference callers
    /// use). Re-storing an identical frame refreshes its position.
    pub fn put(
        &mut self,
        frame: Frame,
        app: &GuiApp,
        window: WindowInfo,
        geometry: DisplayGeometry,
    ) -> String {
        let sha = frame.digest();
        if !self.frames.contains_key(&sha) {
            self.order.push_back(sha.clone());
        }
        self.frames.insert(
            sha.clone(),
            StoredFrame {
                frame,
                app: app.name.clone(),
                window,
                geometry,
            },
        );
        while self.order.len() > MAX_STORED_FRAMES {
            if let Some(old) = self.order.pop_front() {
                self.frames.remove(&old);
            }
        }
        sha
    }

    pub fn get(&self, sha256: &str) -> Option<&StoredFrame> {
        self.frames.get(sha256)
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The grounder seam
// ---------------------------------------------------------------------------

/// An element bounding box on the grounder's 0..=1000 relative
/// scale (S5 curative round, C1): the grounder localizes BOTH
/// edges of the element instead of estimating its centre
/// directly. The S5 frozen benchmark's aim bias — points landing
/// on the element's trailing/bottom edge, 3–19 px outside the
/// text extent while inside the element — is the failure mode of
/// direct centre estimation: the model's point estimate drifts
/// to the end of the text it read. A box makes the centre an
/// arithmetic derivation, not a second estimate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RelBBox {
    pub x_min: f64,
    pub y_min: f64,
    pub x_max: f64,
    pub y_max: f64,
}

impl RelBBox {
    /// The box centre on the relative scale.
    pub fn center(&self) -> (f64, f64) {
        (
            (self.x_min + self.x_max) / 2.0,
            (self.y_min + self.y_max) / 2.0,
        )
    }

    /// Validates the box: ordered edges, on the 0..=1000 scale,
    /// non-degenerate in both axes.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("x_min", self.x_min),
            ("y_min", self.y_min),
            ("x_max", self.x_max),
            ("y_max", self.y_max),
        ] {
            if !(0.0..=1000.0).contains(&value) {
                return Err(format!("bbox {name} {value} is off the 0..=1000 scale"));
            }
        }
        if self.x_max <= self.x_min || self.y_max <= self.y_min {
            return Err(format!(
                "bbox is degenerate or inverted: [{},{}]-[{},{}]",
                self.x_min, self.y_min, self.x_max, self.y_max
            ));
        }
        Ok(())
    }
}

/// An element bounding box in frame pixels (window-relative).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct PixelBBox {
    pub x_min: i32,
    pub y_min: i32,
    pub x_max: i32,
    pub y_max: i32,
}

impl PixelBBox {
    pub fn center(&self) -> (i32, i32) {
        ((self.x_min + self.x_max) / 2, (self.y_min + self.y_max) / 2)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "x_min": self.x_min,
            "y_min": self.y_min,
            "x_max": self.x_max,
            "y_max": self.y_max,
        })
    }
}

/// Converts a relative box into frame pixels, clamped into the
/// frame.
pub fn pixel_bbox_from_rel(rel: RelBBox, frame: &Frame) -> PixelBBox {
    let w = i32::try_from(frame.width).unwrap_or(0);
    let h = i32::try_from(frame.height).unwrap_or(0);
    let conv =
        |value: f64, extent: i32| -> i32 { ((value / 1000.0) * f64::from(extent)).round() as i32 };
    PixelBBox {
        x_min: conv(rel.x_min, w).clamp(0, w.saturating_sub(1).max(0)),
        y_min: conv(rel.y_min, h).clamp(0, h.saturating_sub(1).max(0)),
        x_max: conv(rel.x_max, w).clamp(0, w.saturating_sub(1).max(0)),
        y_max: conv(rel.y_max, h).clamp(0, h.saturating_sub(1).max(0)),
    }
}

/// A grounder's raw answer: the target's center on a 0..=1000
/// relative scale (the scale vision models are asked to answer
/// in, independent of the frame's pixel size), plus confidence.
/// `bbox` carries the element bounds when the grounder supplies
/// them (the C1 curative shape); when present it is
/// authoritative — `rel_x`/`rel_y` are then the box centre, set
/// by the parser, never a separate model estimate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RawGrounding {
    pub rel_x: f64,
    pub rel_y: f64,
    pub confidence: f64,
    pub bbox: Option<RelBBox>,
}

/// A grounding resolved to pixels in a concrete frame:
/// window-relative coordinates (the actuation surface's native
/// frame), ready for confinement checks. `x`/`y` are the act
/// point: the bbox centre when the grounder supplied a box
/// (C1), otherwise the converted point estimate. `bbox` is
/// `None` only for a point-only answer (labelled as such in
/// results: its evidence crop stands in as the bounds record).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GroundHit {
    pub x: i32,
    pub y: i32,
    pub confidence: f64,
    pub bbox: Option<PixelBBox>,
}

/// The pluggable grounding engine. Implementations must be
/// honest: a target that is not visible is an error
/// (`seahawk_gui_ground_failed`), never a guessed point.
pub trait Grounder: Send + Sync {
    /// Route identifier for results and the op log ("ollama").
    fn route_name(&self) -> &'static str;
    /// Locates `target` in `frame`.
    fn ground(&self, frame: &Frame, target: &str) -> GuiResult<RawGrounding>;
    /// Whether `text` is visibly present in `frame` (the
    /// text-presence verification check). Case-insensitive.
    fn text_present(&self, frame: &Frame, text: &str) -> GuiResult<bool>;
}

/// Converts a raw 0..=1000 grounding into frame pixels.
/// Coordinates are clamped into the frame: a model answering a
/// hair outside the edge is imprecise, not malicious, and the
/// confinement check downstream remains the hard boundary.
/// When the answer carries a bbox, the act point is the box
/// centre (C1: the curative correction for the S5 trailing-edge
/// aim bias — the centre is derived, never estimated), and
/// conversion rounds instead of truncating (truncation added a
/// further systematic sub-pixel drift toward the origin).
pub fn hit_from_raw(raw: RawGrounding, frame: &Frame) -> GroundHit {
    let max_x = i32::try_from(frame.width).unwrap_or(0).saturating_sub(1);
    let max_y = i32::try_from(frame.height).unwrap_or(0).saturating_sub(1);
    if let Some(rel) = raw.bbox {
        let bbox = pixel_bbox_from_rel(rel, frame);
        let (cx, cy) = bbox.center();
        return GroundHit {
            x: cx.clamp(0, max_x),
            y: cy.clamp(0, max_y),
            confidence: raw.confidence,
            bbox: Some(bbox),
        };
    }
    let x = (raw.rel_x / 1000.0 * f64::from(frame.width)).round() as i32;
    let y = (raw.rel_y / 1000.0 * f64::from(frame.height)).round() as i32;
    GroundHit {
        x: x.clamp(0, max_x),
        y: y.clamp(0, max_y),
        confidence: raw.confidence,
        bbox: None,
    }
}

/// Validates an agent-supplied answer (the protocol route):
/// window-relative pixel coordinates inside the frame and a
/// confidence within 0..=1. Anything else is an argument error,
/// refused before the answer is used. An optional pixel bbox
/// may accompany the point (C1); when it is present and valid,
/// the act point becomes the box centre — the same derivation
/// as the local route, so both routes aim identically.
pub fn hit_from_agent_answer(
    frame: &Frame,
    x: i64,
    y: i64,
    confidence: f64,
    bbox: Option<PixelBBox>,
) -> GuiResult<GroundHit> {
    if !(0.0..=1.0).contains(&confidence) {
        return Err(GuiError::bad_arguments(
            "agent_answer confidence must be within 0.0..=1.0",
        ));
    }
    if let Some(bbox) = bbox {
        let (w, h) = (i64::from(frame.width), i64::from(frame.height));
        let inside = (0..w).contains(&i64::from(bbox.x_min))
            && (0..w).contains(&i64::from(bbox.x_max))
            && (0..h).contains(&i64::from(bbox.y_min))
            && (0..h).contains(&i64::from(bbox.y_max))
            && bbox.x_max > bbox.x_min
            && bbox.y_max > bbox.y_min;
        if !inside {
            return Err(GuiError::bad_arguments(format!(
                "agent_answer bbox [{},{}]-[{},{}] is degenerate or outside the \
                 frame ({}x{})",
                bbox.x_min, bbox.y_min, bbox.x_max, bbox.y_max, frame.width, frame.height
            )));
        }
        let (cx, cy) = bbox.center();
        return Ok(GroundHit {
            x: cx,
            y: cy,
            confidence,
            bbox: Some(bbox),
        });
    }
    if !(0..i64::from(frame.width)).contains(&x) || !(0..i64::from(frame.height)).contains(&y) {
        return Err(GuiError::bad_arguments(format!(
            "agent_answer point {x},{y} is outside the frame ({}x{})",
            frame.width, frame.height
        )));
    }
    Ok(GroundHit {
        x: i32::try_from(x).unwrap_or(0),
        y: i32::try_from(y).unwrap_or(0),
        confidence,
        bbox: None,
    })
}

// ---------------------------------------------------------------------------
// Ollama grounder (local vision model over loopback HTTP)
// ---------------------------------------------------------------------------

const GROUND_PROMPT: &str = "You are the vision grounding engine of a GUI automation broker. \
Look at the screenshot and locate the UI element described at the end of this prompt. \
Reply with ONLY a JSON object of the form {\"found\": true, \"x_min\": <number>, \
\"y_min\": <number>, \"x_max\": <number>, \"y_max\": <number>, \"confidence\": <number>} where \
x_min/y_min are the element's TOP-LEFT corner and x_max/y_max its BOTTOM-RIGHT corner — the \
bounds of the whole clickable widget (tab, button, menu entry, row), not just its text — on a \
0 to 1000 scale relative to the image (x: 0 = left edge, 1000 = right edge; y: 0 = top edge, \
1000 = bottom edge) and confidence is your certainty between 0 and 1. Localize BOTH edges \
carefully: the broker clicks the centre it derives from your box. If the element is not \
visible in the screenshot, reply {\"found\": false}. No other text. Element: ";

const PRESENCE_PROMPT_PREFIX: &str = "Does this screenshot visibly contain the exact text \"";
const PRESENCE_PROMPT_SUFFIX: &str = "\" (case-insensitive)? Reply with ONLY a JSON object: \
{\"present\": true} or {\"present\": false}. No other text.";

/// The local-model grounder: Ollama's chat API with the frame as
/// an image input. Loopback-only by config validation; blocking
/// HTTP inside `spawn_blocking`, like the downstream client.
pub struct OllamaGrounder {
    client: reqwest::blocking::Client,
    url: String,
    model: String,
}

impl OllamaGrounder {
    pub fn new(url: &str, model: &str, timeout_secs: u64) -> GuiResult<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| {
                GuiError::new(
                    codes::GUI_GROUNDER_UNAVAILABLE,
                    format!("cannot build the grounder HTTP client: {e}"),
                )
            })?;
        Ok(Self {
            client,
            url: url.trim_end_matches('/').to_string(),
            model: model.to_string(),
        })
    }

    /// One image chat round-trip; returns the model's text reply.
    fn chat_image(&self, prompt: &str, frame: &Frame) -> GuiResult<String> {
        let image = base64::engine::general_purpose::STANDARD.encode(&frame.png);
        let body = json!({
            "model": self.model,
            "stream": false,
            "format": "json",
            "options": {"temperature": 0},
            "messages": [{
                "role": "user",
                "content": prompt,
                "images": [image],
            }],
        });
        // Manual JSON body: Seahawk's reqwest is built without
        // the json feature (the downstream client sets the same
        // headers by hand), so serialize explicitly.
        let response = self
            .client
            .post(format!("{}/api/chat", self.url))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|e| {
                GuiError::new(
                    codes::GUI_GROUNDER_UNAVAILABLE,
                    format!(
                        "the local vision grounder at {} cannot be reached: {e}",
                        self.url
                    ),
                )
            })?;
        if !response.status().is_success() {
            return Err(GuiError::new(
                codes::GUI_GROUNDER_UNAVAILABLE,
                format!(
                    "the local vision grounder at {} answered HTTP {}",
                    self.url,
                    response.status()
                ),
            ));
        }
        let text = response.text().map_err(|e| {
            GuiError::new(
                codes::GUI_GROUNDER_UNAVAILABLE,
                format!("the grounder's reply body cannot be read: {e}"),
            )
        })?;
        let payload: Value = serde_json::from_str(&text).map_err(|e| {
            GuiError::new(
                codes::GUI_GROUNDER_UNAVAILABLE,
                format!("the grounder's reply is not JSON: {e}"),
            )
        })?;
        payload
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                GuiError::new(
                    codes::GUI_GROUNDER_UNAVAILABLE,
                    "the grounder's reply has no message content".to_string(),
                )
            })
    }
}

impl Grounder for OllamaGrounder {
    fn route_name(&self) -> &'static str {
        "ollama"
    }

    fn ground(&self, frame: &Frame, target: &str) -> GuiResult<RawGrounding> {
        let reply = self.chat_image(&format!("{GROUND_PROMPT}{target}"), frame)?;
        parse_ground_reply(&reply)
    }

    fn text_present(&self, frame: &Frame, text: &str) -> GuiResult<bool> {
        let reply = self.chat_image(
            &format!("{PRESENCE_PROMPT_PREFIX}{text}{PRESENCE_PROMPT_SUFFIX}"),
            frame,
        )?;
        parse_presence_reply(&reply)
    }
}

/// Extracts the first JSON object from a model reply (models
/// wrap JSON in prose or code fences often enough that demanding
/// a bare object would make the route useless; the object is
/// still parsed strictly once located).
fn extract_json_object(reply: &str) -> Option<Value> {
    let start = reply.find('{')?;
    let end = reply.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&reply[start..=end]).ok()
}

/// Parses a grounding reply. `found: false`, missing fields, or
/// coordinates off the 0..=1000 scale are typed ground failures —
/// the broker would rather refuse than click a hallucination.
/// The C1 shape carries a bbox (`x_min`/`y_min`/`x_max`/`y_max`):
/// when all four are present they must validate, and the point
/// becomes the box centre. A point-only reply (`x`/`y`, the
/// pre-C1 shape) is still accepted — it degrades to a point
/// answer with no bbox, labelled as such downstream — so a model
/// that ignores the box instruction fails soft, never silently
/// "succeeds" with invented bounds.
pub fn parse_ground_reply(reply: &str) -> GuiResult<RawGrounding> {
    let Some(object) = extract_json_object(reply) else {
        return Err(GuiError::new(
            codes::GUI_GROUND_FAILED,
            "the grounder's reply contains no JSON object".to_string(),
        ));
    };
    if object.get("found").and_then(Value::as_bool) == Some(false) {
        return Err(GuiError::new(
            codes::GUI_GROUND_FAILED,
            "the grounder reports the target is not visible in the frame".to_string(),
        ));
    }
    // A missing confidence is read as 0.5: models omit it often,
    // and the configured floor then decides honestly.
    let confidence = object
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.5)
        .clamp(0.0, 1.0);
    let bbox_fields =
        ["x_min", "y_min", "x_max", "y_max"].map(|key| object.get(key).and_then(Value::as_f64));
    if let [Some(x_min), Some(y_min), Some(x_max), Some(y_max)] = bbox_fields {
        let bbox = RelBBox {
            x_min,
            y_min,
            x_max,
            y_max,
        };
        if let Err(reason) = bbox.validate() {
            return Err(GuiError::new(
                codes::GUI_GROUND_FAILED,
                format!("the grounder answered an invalid bbox: {reason}"),
            ));
        }
        let (rel_x, rel_y) = bbox.center();
        return Ok(RawGrounding {
            rel_x,
            rel_y,
            confidence,
            bbox: Some(bbox),
        });
    }
    let (Some(x), Some(y)) = (
        object.get("x").and_then(Value::as_f64),
        object.get("y").and_then(Value::as_f64),
    ) else {
        return Err(GuiError::new(
            codes::GUI_GROUND_FAILED,
            "the grounder's reply has neither a bbox (x_min/y_min/x_max/y_max) \
             nor numeric x/y"
                .to_string(),
        ));
    };
    if !(0.0..=1000.0).contains(&x) || !(0.0..=1000.0).contains(&y) {
        return Err(GuiError::new(
            codes::GUI_GROUND_FAILED,
            format!("the grounder answered off-scale coordinates {x},{y} (scale is 0..=1000)"),
        ));
    }
    Ok(RawGrounding {
        rel_x: x,
        rel_y: y,
        confidence,
        bbox: None,
    })
}

/// Parses a text-presence reply.
pub fn parse_presence_reply(reply: &str) -> GuiResult<bool> {
    let Some(object) = extract_json_object(reply) else {
        return Err(GuiError::new(
            codes::GUI_GROUND_FAILED,
            "the grounder's presence reply contains no JSON object".to_string(),
        ));
    };
    object
        .get("present")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            GuiError::new(
                codes::GUI_GROUND_FAILED,
                "the grounder's presence reply has no boolean \"present\"".to_string(),
            )
        })
}

// ---------------------------------------------------------------------------
// Frame pixel work (evidence crops, change detection)
// ---------------------------------------------------------------------------

/// Decodes one of the broker's own PNG frames to RGB8 pixels.
/// The broker only ever decodes frames it encoded itself (RGB8),
/// but RGBA/grayscale inputs are normalized rather than refused.
pub fn decode_png_rgb(frame: &Frame) -> GuiResult<(Vec<u8>, u32, u32)> {
    let decoder = png::Decoder::new(Cursor::new(&frame.png));
    let mut reader = decoder
        .read_info()
        .map_err(|e| GuiError::failed(format!("png decode info: {e}")))?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|e| GuiError::failed(format!("png decode frame: {e}")))?;
    buf.truncate(info.buffer_size());
    let (width, height) = (info.width, info.height);
    let rgb = match info.color_type {
        png::ColorType::Rgb => buf,
        png::ColorType::Rgba => buf
            .as_chunks::<4>()
            .0
            .iter()
            .flat_map(|px| [px[0], px[1], px[2]])
            .collect(),
        png::ColorType::Grayscale => buf.iter().flat_map(|g| [*g, *g, *g]).collect(),
        png::ColorType::GrayscaleAlpha => buf
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|px| [px[0], px[0], px[0]])
            .collect(),
        png::ColorType::Indexed => {
            return Err(GuiError::failed(
                "indexed-color PNG frames are not supported for pixel work".to_string(),
            ));
        }
    };
    Ok((rgb, width, height))
}

fn encode_png_rgb(rgb: &[u8], width: u32, height: u32) -> GuiResult<Vec<u8>> {
    let mut png = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|e| GuiError::failed(format!("png header: {e}")))?;
        writer
            .write_image_data(rgb)
            .map_err(|e| GuiError::failed(format!("png data: {e}")))?;
    }
    Ok(png)
}

/// Cuts the evidence crop around a grounded point: the region a
/// human reviewer (or the D-207 loop) looks at to judge whether
/// the grounder pointed at the right thing.
pub fn evidence_crop(frame: &Frame, cx: i32, cy: i32) -> GuiResult<Frame> {
    let (rgb, width, height) = decode_png_rgb(frame)?;
    let (w, h) = (width as i32, height as i32);
    let x0 = (cx - EVIDENCE_CROP_HALF).clamp(0, w);
    let x1 = (cx + EVIDENCE_CROP_HALF + 1).clamp(0, w);
    let y0 = (cy - EVIDENCE_CROP_HALF).clamp(0, h);
    let y1 = (cy + EVIDENCE_CROP_HALF + 1).clamp(0, h);
    if x1 <= x0 || y1 <= y0 {
        return Err(GuiError::failed(format!(
            "evidence crop around {cx},{cy} is empty in a {w}x{h} frame"
        )));
    }
    let (cw, ch) = ((x1 - x0) as usize, (y1 - y0) as usize);
    let mut out = Vec::with_capacity(cw * ch * 3);
    for row in y0..y1 {
        let start = (row as usize * width as usize + x0 as usize) * 3;
        out.extend_from_slice(&rgb[start..start + cw * 3]);
    }
    Ok(Frame {
        png: encode_png_rgb(&out, cw as u32, ch as u32)?,
        width: cw as u32,
        height: ch as u32,
    })
}

/// Per-channel tolerance of the blank-frame screen (C4): a
/// pixel counts as "the frame's single colour" when every
/// channel is within this distance of the reference colour.
pub const BLANK_CHANNEL_TOLERANCE: u8 = 10;
/// Fraction of pixels that must match the single colour for a
/// frame to be suspected blank (SPEC §6.1 step 3: >99%).
pub const BLANK_FRACTION: f64 = 0.99;

/// The content class of a frame (C4 blank-frame screen, Phoenix
/// REQ-2): a frame whose pixels are (nearly) all one colour
/// carries no verifiable content — an unpainted window, a
/// crashed renderer — whatever its capture reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameContent {
    Content,
    SuspectBlank,
}

/// Classifies a frame by the blank-frame screen: decode, take
/// the first pixel as the reference colour, and count pixels
/// within BLANK_CHANNEL_TOLERANCE of it on every channel. Above
/// BLANK_FRACTION the frame is `SuspectBlank`. A decode failure
/// is a typed failure, never a silent "content" verdict.
pub fn frame_content(frame: &Frame) -> GuiResult<FrameContent> {
    let (rgb, _, _) = decode_png_rgb(frame)?;
    if rgb.len() < 3 {
        return Ok(FrameContent::SuspectBlank);
    }
    let reference = [rgb[0], rgb[1], rgb[2]];
    let total = rgb.len() / 3;
    let matching = rgb
        .as_chunks::<3>()
        .0
        .iter()
        .filter(|px| (0..3).all(|c| px[c].abs_diff(reference[c]) <= BLANK_CHANNEL_TOLERANCE))
        .count();
    let fraction = matching as f64 / total.max(1) as f64;
    Ok(if fraction > BLANK_FRACTION {
        FrameContent::SuspectBlank
    } else {
        FrameContent::Content
    })
}

/// Fraction of pixels in the region around (cx, cy) whose color
/// changed between two frames by more than DIFF_PIXEL_THRESHOLD
/// in any channel. Frames of different sizes are a typed failure:
/// the comparison would be meaningless.
pub fn region_diff_fraction(a: &Frame, b: &Frame, cx: i32, cy: i32) -> GuiResult<f64> {
    region_diff_fraction_ranged(a, b, cx, cy, DIFF_REGION_HALF)
}

/// `region_diff_fraction` with an explicit half-size. A very
/// large half-size covers the whole frame (the clamps bound the
/// region to the frame), which is how the full-frame mode of
/// the `changed` check (C3) is expressed.
pub fn region_diff_fraction_ranged(
    a: &Frame,
    b: &Frame,
    cx: i32,
    cy: i32,
    half: i32,
) -> GuiResult<f64> {
    if a.width != b.width || a.height != b.height {
        return Err(GuiError::failed(format!(
            "cannot diff frames of different sizes ({}x{} vs {}x{})",
            a.width, a.height, b.width, b.height
        )));
    }
    let (pa, _, _) = decode_png_rgb(a)?;
    let (pb, _, _) = decode_png_rgb(b)?;
    let (w, h) = (a.width as i32, a.height as i32);
    let x0 = (cx - half).clamp(0, w);
    let x1 = (cx + half + 1).clamp(0, w);
    let y0 = (cy - half).clamp(0, h);
    let y1 = (cy + half + 1).clamp(0, h);
    if x1 <= x0 || y1 <= y0 {
        return Err(GuiError::failed(format!(
            "diff region around {cx},{cy} is empty in a {w}x{h} frame"
        )));
    }
    let mut changed = 0u64;
    let mut total = 0u64;
    for row in y0..y1 {
        for col in x0..x1 {
            let idx = (row as usize * a.width as usize + col as usize) * 3;
            let differs = (0..3).any(|c| pa[idx + c].abs_diff(pb[idx + c]) > DIFF_PIXEL_THRESHOLD);
            total += 1;
            if differs {
                changed += 1;
            }
        }
    }
    Ok(changed as f64 / total as f64)
}

// ---------------------------------------------------------------------------
// Verification expectations
// ---------------------------------------------------------------------------

/// The machine-checkable part of an `expect` argument. At least
/// one check must be present: `gui.act_verified` without a check
/// is just `gui.<app>.actuate` with extra steps, and the tool
/// refuses that shape rather than pretending to verify.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Expectation {
    /// The frame region around the action point changed.
    pub changed: Option<bool>,
    /// C3 anchor for the `changed` check: diff the region
    /// centred on this window-relative point instead of the
    /// action point — for effects that anchor away from where
    /// the action landed (menus at the top-left, Blender's F3
    /// search at the top-right; S5 finding G-1).
    pub changed_around: Option<(i32, i32)>,
    /// C3: diff the whole frame for the `changed` check instead
    /// of a region. Also the broker's own default for actions
    /// that carry no point (key presses): a point-less action
    /// has no meaningful "region around the point", and the S5
    /// window-centre fallback is exactly what made menu closes
    /// unverifiable (G-1).
    pub full_frame: bool,
    /// The target window's title contains this text
    /// (case-insensitive) after the action.
    pub title_contains: Option<String>,
    /// The target app's window holds input focus after the action.
    pub focused: Option<bool>,
    /// This text is visibly present in the post-action frame
    /// (evaluated by the local grounder; routes that cannot
    /// evaluate it refuse the call before acting).
    pub text_visible: Option<String>,
    /// Free-text description of the expected effect, carried into
    /// results and the op log target for human readers. Not a
    /// machine check.
    pub description: Option<String>,
}

impl Expectation {
    pub fn has_machine_check(&self) -> bool {
        self.changed.is_some()
            || self.title_contains.is_some()
            || self.focused.is_some()
            || self.text_visible.is_some()
    }

    pub fn parse(args: &Value) -> GuiResult<Self> {
        let Some(expect) = args.get("expect") else {
            return Err(GuiError::bad_arguments(
                "gui.act_verified requires an \"expect\" object with at least one \
                 machine check (changed | title_contains | focused | text_visible): \
                 an unverified actuation is gui.<app>.actuate's job",
            ));
        };
        let Some(object) = expect.as_object() else {
            return Err(GuiError::bad_arguments("\"expect\" must be an object"));
        };
        let mut parsed = Self::default();
        for (key, value) in object {
            match key.as_str() {
                "changed" => {
                    parsed.changed = Some(value.as_bool().ok_or_else(|| {
                        GuiError::bad_arguments("\"expect.changed\" must be a boolean")
                    })?);
                }
                "changed_around" => {
                    let (Some(x), Some(y)) = (
                        value.get("x").and_then(Value::as_i64),
                        value.get("y").and_then(Value::as_i64),
                    ) else {
                        return Err(GuiError::bad_arguments(
                            "\"expect.changed_around\" must be an object with \
                             integer x and y (window-relative)",
                        ));
                    };
                    let (Ok(x), Ok(y)) = (i32::try_from(x), i32::try_from(y)) else {
                        return Err(GuiError::bad_arguments(
                            "\"expect.changed_around\" coordinates are out of range",
                        ));
                    };
                    parsed.changed_around = Some((x, y));
                }
                "full_frame" => {
                    parsed.full_frame = value.as_bool().ok_or_else(|| {
                        GuiError::bad_arguments("\"expect.full_frame\" must be a boolean")
                    })?;
                }
                "title_contains" => {
                    parsed.title_contains = Some(
                        value
                            .as_str()
                            .ok_or_else(|| {
                                GuiError::bad_arguments(
                                    "\"expect.title_contains\" must be a string",
                                )
                            })?
                            .to_string(),
                    );
                }
                "focused" => {
                    parsed.focused = Some(value.as_bool().ok_or_else(|| {
                        GuiError::bad_arguments("\"expect.focused\" must be a boolean")
                    })?);
                }
                "text_visible" => {
                    parsed.text_visible = Some(
                        value
                            .as_str()
                            .ok_or_else(|| {
                                GuiError::bad_arguments("\"expect.text_visible\" must be a string")
                            })?
                            .to_string(),
                    );
                }
                "description" => {
                    parsed.description = Some(
                        value
                            .as_str()
                            .ok_or_else(|| {
                                GuiError::bad_arguments("\"expect.description\" must be a string")
                            })?
                            .to_string(),
                    );
                }
                other => {
                    return Err(GuiError::bad_arguments(format!(
                        "unknown \"expect\" key {other:?}: the checks are changed | \
                         title_contains | focused | text_visible, the changed-check \
                         anchors changed_around | full_frame, plus a free-text \
                         description"
                    )));
                }
            }
        }
        if !parsed.has_machine_check() {
            return Err(GuiError::bad_arguments(
                "\"expect\" carries no machine check (changed | title_contains | \
                 focused | text_visible): refusing to act unverified",
            ));
        }
        Ok(parsed)
    }
}

/// One evaluated verification check.
#[derive(Clone, Debug, Serialize)]
pub struct CheckOutcome {
    pub check: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// Evaluates every check in the expectation against the action's
/// bracket frames and a fresh post-action capture. `grounder` is
/// required iff `expect.text_visible` is set (the caller refuses
/// earlier when it cannot supply one).
pub fn evaluate_checks(
    expect: &Expectation,
    pre: &Frame,
    post: &Frame,
    post_window: &WindowInfo,
    point: (i32, i32),
    grounder: Option<&dyn Grounder>,
) -> Vec<CheckOutcome> {
    let mut outcomes = Vec::new();
    if let Some(want_changed) = expect.changed {
        // Where the diff looks (C3): an explicit anchor wins,
        // then full-frame mode, then the region around the
        // action point (the pre-C3 default, unchanged).
        let (mode, diff) = if let Some((ax, ay)) = expect.changed_around {
            (
                format!("anchored at {ax},{ay}"),
                region_diff_fraction(pre, post, ax, ay),
            )
        } else if expect.full_frame {
            (
                "full frame".to_string(),
                region_diff_fraction_ranged(
                    pre,
                    post,
                    i32::try_from(pre.width / 2).unwrap_or(0),
                    i32::try_from(pre.height / 2).unwrap_or(0),
                    i32::MAX / 2,
                ),
            )
        } else {
            (
                format!("region around {},{}", point.0, point.1),
                region_diff_fraction(pre, post, point.0, point.1),
            )
        };
        let (passed, detail) = match diff {
            Ok(fraction) => {
                let observed_changed = fraction >= DIFF_CHANGED_FRACTION;
                (
                    observed_changed == want_changed,
                    format!(
                        "{mode} diff fraction {fraction:.4} (threshold {DIFF_CHANGED_FRACTION})"
                    ),
                )
            }
            Err(e) => (false, format!("diff failed: {}", e.message)),
        };
        outcomes.push(CheckOutcome {
            check: "changed",
            passed,
            detail,
        });
    }
    if let Some(needle) = &expect.title_contains {
        let passed = post_window
            .title
            .to_lowercase()
            .contains(&needle.to_lowercase());
        outcomes.push(CheckOutcome {
            check: "title_contains",
            passed,
            detail: format!("post-action window title is {:?}", post_window.title),
        });
    }
    if let Some(want_focused) = expect.focused {
        outcomes.push(CheckOutcome {
            check: "focused",
            passed: post_window.focused == want_focused,
            detail: format!(
                "post-action target window focused = {}",
                post_window.focused
            ),
        });
    }
    if let Some(text) = &expect.text_visible {
        let (passed, detail) = match grounder {
            Some(grounder) => match grounder.text_present(post, text) {
                Ok(present) => (present, format!("grounder presence check for {text:?}")),
                Err(e) => (false, format!("presence check failed: {}", e.message)),
            },
            None => (
                false,
                "no grounder available to evaluate text_visible".to_string(),
            ),
        };
        outcomes.push(CheckOutcome {
            check: "text_visible",
            passed,
            detail,
        });
    }
    outcomes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_frame(width: u32, height: u32, rgb: [u8; 3]) -> Frame {
        // Row-major RGB of the solid color.
        let mut data = Vec::with_capacity((width * height * 3) as usize);
        for _ in 0..(width * height) {
            data.extend_from_slice(&rgb);
        }
        Frame {
            png: encode_png_rgb(&data, width, height).expect("encode"),
            width,
            height,
        }
    }

    fn app() -> GuiApp {
        GuiApp {
            name: "blender".to_string(),
            display_name: "Blender".to_string(),
            window_match: vec!["Blender".to_string()],
        }
    }

    fn window(width: u32, height: u32) -> WindowInfo {
        WindowInfo {
            id: 42,
            wm_class: "Blender".to_string(),
            instance: "blender".to_string(),
            title: "Blender".to_string(),
            x: 10,
            y: 20,
            width,
            height,
            focused: true,
            matched: true,
        }
    }

    fn geometry() -> DisplayGeometry {
        DisplayGeometry {
            display: Some(":98".to_string()),
            root_width: 1600,
            root_height: 1000,
            width_mm: Some(423),
            height_mm: Some(264),
            scale_factor: 1.0,
            virtual_display: true,
        }
    }

    #[test]
    fn frame_store_is_bounded_and_keyed_by_digest() {
        let mut store = FrameStore::new();
        let app = app();
        for i in 0..(MAX_STORED_FRAMES + 4) {
            let frame = solid_frame(8, 8, [i as u8, 0, 0]);
            store.put(frame, &app, window(8, 8), geometry());
        }
        assert_eq!(store.len(), MAX_STORED_FRAMES);
        let frame = solid_frame(8, 8, [200, 1, 2]);
        let sha = store.put(frame, &app, window(8, 8), geometry());
        assert!(store.get(&sha).is_some());
        assert!(store.get(&"0".repeat(64)).is_none());
    }

    #[test]
    fn raw_grounding_converts_and_clamps() {
        let frame = solid_frame(200, 100, [9, 9, 9]);
        let hit = hit_from_raw(
            RawGrounding {
                rel_x: 500.0,
                rel_y: 250.0,
                confidence: 0.9,
                bbox: None,
            },
            &frame,
        );
        assert_eq!((hit.x, hit.y), (100, 25));
        let edge = hit_from_raw(
            RawGrounding {
                rel_x: 1000.0,
                rel_y: 1000.0,
                confidence: 1.0,
                bbox: None,
            },
            &frame,
        );
        assert_eq!((edge.x, edge.y), (199, 99));
    }

    #[test]
    fn agent_answer_is_bounds_checked() {
        let frame = solid_frame(100, 50, [0, 0, 0]);
        assert!(hit_from_agent_answer(&frame, 50, 25, 0.8, None).is_ok());
        match hit_from_agent_answer(&frame, 100, 25, 0.8, None) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(h) => panic!("out-of-frame answer accepted: {h:?}"),
        }
        match hit_from_agent_answer(&frame, 50, 25, 1.5, None) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(h) => panic!("over-confident answer accepted: {h:?}"),
        }
    }

    #[test]
    fn ground_reply_parsing_is_strict_but_forgiving_of_wrapping() {
        let bare =
            parse_ground_reply("{\"found\": true, \"x\": 512, \"y\": 300, \"confidence\": 0.9}")
                .expect("bare");
        assert_eq!((bare.rel_x, bare.rel_y), (512.0, 300.0));
        let fenced =
            parse_ground_reply("Here is the location:\n```json\n{\"x\": 100, \"y\": 200}\n```")
                .expect("fenced");
        assert_eq!(fenced.confidence, 0.5, "missing confidence reads as 0.5");
        match parse_ground_reply("{\"found\": false}") {
            Err(e) => assert_eq!(e.code, codes::GUI_GROUND_FAILED),
            Ok(r) => panic!("not-found accepted: {r:?}"),
        }
        match parse_ground_reply("{\"x\": 1200, \"y\": 10}") {
            Err(e) => assert_eq!(e.code, codes::GUI_GROUND_FAILED),
            Ok(r) => panic!("off-scale accepted: {r:?}"),
        }
        match parse_ground_reply("I cannot see it") {
            Err(e) => assert_eq!(e.code, codes::GUI_GROUND_FAILED),
            Ok(r) => panic!("prose accepted: {r:?}"),
        }
    }

    #[test]
    fn presence_reply_parsing() {
        assert!(parse_presence_reply("{\"present\": true}").expect("present"));
        assert!(!parse_presence_reply("{\"present\": false}").expect("absent"));
        assert!(parse_presence_reply("{\"visible\": true}").is_err());
    }

    #[test]
    fn region_diff_measures_change() {
        let a = solid_frame(300, 300, [10, 10, 10]);
        let b = solid_frame(300, 300, [10, 10, 10]);
        assert_eq!(region_diff_fraction(&a, &b, 150, 150).expect("diff"), 0.0);
        let c = solid_frame(300, 300, [240, 240, 240]);
        assert_eq!(region_diff_fraction(&a, &c, 150, 150).expect("diff"), 1.0);
        let small = solid_frame(100, 100, [0, 0, 0]);
        match region_diff_fraction(&a, &small, 10, 10) {
            Err(e) => assert_eq!(e.code, codes::GUI_ACTION_FAILED),
            Ok(f) => panic!("size-mismatched diff accepted: {f}"),
        }
    }

    #[test]
    fn evidence_crop_is_centered_and_clipped() {
        let frame = solid_frame(400, 400, [7, 7, 7]);
        let crop = evidence_crop(&frame, 200, 200).expect("crop");
        assert_eq!((crop.width, crop.height), (241, 241));
        let corner = evidence_crop(&frame, 0, 0).expect("corner crop");
        assert_eq!((corner.width, corner.height), (121, 121));
    }

    #[test]
    fn expectation_requires_a_machine_check() {
        match Expectation::parse(&json!({})) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(x) => panic!("missing expect accepted: {x:?}"),
        }
        match Expectation::parse(&json!({"expect": {"description": "it opens"}})) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(x) => panic!("description-only expect accepted: {x:?}"),
        }
        match Expectation::parse(&json!({"expect": {"bogus": true}})) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(x) => panic!("unknown expect key accepted: {x:?}"),
        }
        let ok =
            Expectation::parse(&json!({"expect": {"changed": true, "title_contains": "Save"}}))
                .expect("expect");
        assert!(ok.has_machine_check());
        assert_eq!(ok.title_contains.as_deref(), Some("Save"));
    }

    struct FixedGrounder {
        present: bool,
    }

    impl Grounder for FixedGrounder {
        fn route_name(&self) -> &'static str {
            "fixed-test"
        }
        fn ground(&self, _frame: &Frame, _target: &str) -> GuiResult<RawGrounding> {
            Ok(RawGrounding {
                rel_x: 500.0,
                rel_y: 500.0,
                confidence: 0.99,
                bbox: None,
            })
        }
        fn text_present(&self, _frame: &Frame, _text: &str) -> GuiResult<bool> {
            Ok(self.present)
        }
    }

    #[test]
    fn checks_evaluate_against_frames_and_window() {
        let pre = solid_frame(300, 300, [0, 0, 0]);
        let post = solid_frame(300, 300, [255, 255, 255]);
        let mut win = window(300, 300);
        win.title = "Save As — Blender".to_string();
        let expect = Expectation::parse(
            &json!({"expect": {"changed": true, "title_contains": "save", "focused": true, "text_visible": "Save"}}),
        )
        .expect("expect");
        let grounder = FixedGrounder { present: true };
        let outcomes = evaluate_checks(&expect, &pre, &post, &win, (150, 150), Some(&grounder));
        assert_eq!(outcomes.len(), 4);
        assert!(outcomes.iter().all(|o| o.passed), "{outcomes:?}");
        let absent = FixedGrounder { present: false };
        let outcomes = evaluate_checks(&expect, &pre, &post, &win, (150, 150), Some(&absent));
        assert!(
            outcomes
                .iter()
                .any(|o| !o.passed && o.check == "text_visible")
        );
    }

    // ---- S5 curative round (C1/C3/C4) ----

    #[test]
    fn bbox_reply_aims_at_the_box_centre_not_the_trailing_edge() {
        // The S5 failure shape: a tab whose text extent ends at
        // rel x=389 while the widget runs to 420. A point answer
        // at the text's trailing edge (395) missed the text box;
        // the box answer's centre is derived arithmetically.
        let parsed = parse_ground_reply(
            "{\"found\": true, \"x_min\": 340, \"y_min\": 10, \"x_max\": 420, \
             \"y_max\": 30, \"confidence\": 0.95}",
        )
        .expect("bbox reply");
        let bbox = parsed.bbox.expect("bbox carried");
        assert_eq!((parsed.rel_x, parsed.rel_y), (380.0, 20.0));
        assert_eq!(bbox.x_max, 420.0);
        let frame = solid_frame(1000, 500, [1, 2, 3]);
        let hit = hit_from_raw(parsed, &frame);
        assert_eq!((hit.x, hit.y), (380, 10));
        assert_eq!(
            hit.bbox,
            Some(PixelBBox {
                x_min: 340,
                y_min: 5,
                x_max: 420,
                y_max: 15
            })
        );
    }

    #[test]
    fn bbox_reply_must_validate() {
        for bad in [
            "{\"x_min\": 500, \"y_min\": 10, \"x_max\": 400, \"y_max\": 30}",
            "{\"x_min\": 100, \"y_min\": 10, \"x_max\": 100, \"y_max\": 30}",
            "{\"x_min\": -5, \"y_min\": 10, \"x_max\": 400, \"y_max\": 30}",
            "{\"x_min\": 100, \"y_min\": 10, \"x_max\": 1200, \"y_max\": 30}",
        ] {
            match parse_ground_reply(bad) {
                Err(e) => assert_eq!(e.code, codes::GUI_GROUND_FAILED, "{bad}"),
                Ok(r) => panic!("invalid bbox accepted: {bad} -> {r:?}"),
            }
        }
        // A point-only reply still parses (degraded, no bbox).
        let point = parse_ground_reply("{\"x\": 250, \"y\": 250}").expect("point reply");
        assert_eq!(point.bbox, None);
    }

    #[test]
    fn agent_answer_with_bbox_aims_at_its_centre() {
        let frame = solid_frame(400, 200, [0, 0, 0]);
        let bbox = PixelBBox {
            x_min: 100,
            y_min: 40,
            x_max: 180,
            y_max: 60,
        };
        // The caller's point sits at the box's trailing edge; the
        // derived centre is what gets acted on.
        let hit = hit_from_agent_answer(&frame, 179, 59, 0.9, Some(bbox)).expect("hit");
        assert_eq!((hit.x, hit.y), (140, 50));
        assert_eq!(hit.bbox, Some(bbox));
        let outside = PixelBBox {
            x_min: 390,
            y_min: 40,
            x_max: 450,
            y_max: 60,
        };
        assert!(hit_from_agent_answer(&frame, 10, 10, 0.9, Some(outside)).is_err());
    }

    #[test]
    fn blank_frame_screen_flags_uniform_frames_only() {
        let blank = solid_frame(64, 64, [12, 12, 14]);
        assert_eq!(
            frame_content(&blank).expect("screen"),
            FrameContent::SuspectBlank
        );
        // Two-tone frame: half dark, half bright — real content.
        let mut data = Vec::new();
        for row in 0..64 {
            for _ in 0..64 {
                data.extend_from_slice(if row < 32 {
                    &[0, 0, 0]
                } else {
                    &[250, 250, 250]
                });
            }
        }
        let content = Frame {
            png: encode_png_rgb(&data, 64, 64).expect("encode"),
            width: 64,
            height: 64,
        };
        assert_eq!(
            frame_content(&content).expect("screen"),
            FrameContent::Content
        );
    }

    #[test]
    fn changed_check_honours_anchor_and_full_frame() {
        // Change confined to the top-left corner: invisible to a
        // centre-region diff (the S5 G-1 failure), visible to an
        // anchored diff and to a full-frame diff.
        let (w, h) = (400usize, 400usize);
        let a = vec![0u8; w * h * 3];
        let mut b = vec![0u8; w * h * 3];
        for row in 0..60 {
            for col in 0..60 {
                let idx = (row * w + col) * 3;
                b[idx..idx + 3].copy_from_slice(&[255, 255, 255]);
            }
        }
        let pre = Frame {
            png: encode_png_rgb(&a, 400, 400).expect("encode"),
            width: 400,
            height: 400,
        };
        let post = Frame {
            png: encode_png_rgb(&b, 400, 400).expect("encode"),
            width: 400,
            height: 400,
        };
        let win = window(400, 400);
        let plain = Expectation::parse(&json!({"expect": {"changed": true}})).expect("expect");
        let outcomes = evaluate_checks(&plain, &pre, &post, &win, (200, 200), None);
        assert!(
            !outcomes[0].passed,
            "centre region must miss it: {outcomes:?}"
        );
        let anchored = Expectation::parse(
            &json!({"expect": {"changed": true, "changed_around": {"x": 30, "y": 30}}}),
        )
        .expect("expect");
        let outcomes = evaluate_checks(&anchored, &pre, &post, &win, (200, 200), None);
        assert!(
            outcomes[0].passed,
            "anchored diff must see it: {outcomes:?}"
        );
        assert!(outcomes[0].detail.contains("anchored at 30,30"));
        let full = Expectation::parse(&json!({"expect": {"changed": true, "full_frame": true}}))
            .expect("expect");
        let outcomes = evaluate_checks(&full, &pre, &post, &win, (200, 200), None);
        // 60x60 of 400x400 = 2.25% > the 1% threshold.
        assert!(
            outcomes[0].passed,
            "full-frame diff must see it: {outcomes:?}"
        );
        assert!(outcomes[0].detail.contains("full frame"));
    }

    #[test]
    fn expectation_rejects_malformed_anchors() {
        match Expectation::parse(&json!({"expect": {"changed": true, "changed_around": {"x": 1}}}))
        {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(x) => panic!("anchor without y accepted: {x:?}"),
        }
        match Expectation::parse(&json!({"expect": {"changed": true, "full_frame": "yes"}})) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(x) => panic!("non-boolean full_frame accepted: {x:?}"),
        }
    }
}
