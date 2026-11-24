# seahawk_stroke_provider.py — the Blender stroke-data provider.
#
# A single-file Blender addon (run as a script, not installed)
# that serves the seahawk Blender surface (DESIGN,
# seahawk-blender-20261124) from inside a pinned Blender 5.3.0
# session: stroke artifacts in, deterministic scene data out.
# Drawing is data here: paint is rasterized by this provider
# with a tiny fixed brush model, shells are swept with
# parallel-transport frames, Grease Pencil strokes are read and
# written as plain data. Blender's interactive brush engine is
# never invoked (policy-excluded, DESIGN §3).
#
# Discipline (local-tiger-style-blender): faulthandler first;
# hold names, not RNA references; bpy.data / bmesh over bpy.ops
# wherever an operator is not the point; no threads and no
# timers — the HTTP server runs on the main thread and blocks
# the (background, factory-startup) session; every op is a data
# op that works headless.
#
# Launch (canonical argv, -Y always, never -y):
#   blender -b -Y --factory-startup --offline-mode -noaudio \
#       --python-exit-code 1 -P seahawk_stroke_provider.py
# Configuration rides the environment:
#   SEAHAWK_PROVIDER_SECRET  (required; the provider's only auth)
#   SEAHAWK_PROVIDER_PORT    (default 8471)
#
# Protocol: JSON-RPC 2.0 over HTTP POST on 127.0.0.1. Every
# request carries X-Seahawk-Provider-Secret; `initialize` issues
# a session id that later requests carry as
# X-Seahawk-Session-Id (a missing/stale id answers the
# session-invalid error -32001, the broker re-initializes once).

import faulthandler

faulthandler.enable()

import hashlib
import json
import math
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import bpy
from mathutils import Quaternion, Vector

PROVIDER_NAME = "seahawk-stroke-provider"
PROVIDER_VERSION = "1.0.0"
SCHEMA = "seahawk.stroke/v1"

# Artifact bounds (DESIGN §2): refused, never truncated.
MAX_STROKES = 4096
MAX_POINTS_PER_STROKE = 8192
MAX_POINTS_TOTAL = 2_000_000

# The determinism exclusion set (DESIGN §3): keys refused by
# name wherever they appear in an artifact. Mirrors the
# broker-side validator (seahawk src/stroke.rs) exactly.
EXCLUDED_KEYS = {
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
}

SESSION_INVALID = -32001
INVALID_PARAMS = -32602
PROVIDER_ERROR = -32000


class ProviderError(Exception):
    def __init__(self, message, code=PROVIDER_ERROR):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical JSON + content hash (byte-identical with the broker:
# seahawk src/stroke.rs — sorted keys, no whitespace, every JSON
# number rendered as a quoted 6-decimal string, strings escaped
# the serde_json way, which json.dumps matches for the escapes
# both emit: \" \\ \b \f \n \r \t and \u00XX for other controls)
# ---------------------------------------------------------------------------

def canonical_bytes(value):
    parts = []
    _write_canonical(value, parts)
    return "".join(parts).encode("utf-8")


def _write_canonical(value, parts):
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, (int, float)):
        parts.append(json.dumps("%.6f" % float(value), ensure_ascii=False))
    elif isinstance(value, str):
        parts.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, list):
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _write_canonical(item, parts)
        parts.append("]")
    elif isinstance(value, dict):
        parts.append("{")
        for index, key in enumerate(sorted(value.keys())):
            if index:
                parts.append(",")
            parts.append(json.dumps(key, ensure_ascii=False))
            parts.append(":")
            _write_canonical(value[key], parts)
        parts.append("}")
    else:
        raise ProviderError("uncanonical value of type %s" % type(value).__name__)


def content_hash(envelope):
    stripped = {k: v for k, v in envelope.items() if k != "sha256"}
    return hashlib.sha256(canonical_bytes(stripped)).hexdigest()


def dec(text, what):
    """Parses a 6-decimal string (D2) to a float, strictly."""
    if not isinstance(text, str):
        raise ProviderError("%s must be a 6-decimal string, got %r" % (what, text))
    body = text[1:] if text.startswith("-") else text
    whole, dot, frac = body.partition(".")
    if not dot or len(frac) != 6 or not whole.isdigit() or not frac.isdigit():
        raise ProviderError("%s is not a 6-decimal string: %r" % (what, text))
    return float(text)


def fmt6(value):
    return "%.6f" % float(value)


# ---------------------------------------------------------------------------
# Artifact validation (mirror of the broker-side validator:
# same rules, same refusals — defense in depth, DESIGN §5)
# ---------------------------------------------------------------------------

def _scan_excluded(value, path):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in EXCLUDED_KEYS:
                raise ProviderError(
                    "excluded feature %r at %s: refused by the determinism "
                    "policy (DESIGN §3)" % (key, path)
                )
            _scan_excluded(item, "%s.%s" % (path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_excluded(item, "%s[%d]" % (path, index))


def validate_artifact(artifact):
    """Returns (kind, info) or raises ProviderError."""
    if not isinstance(artifact, dict):
        raise ProviderError("artifact must be a JSON object")
    _scan_excluded(artifact, "artifact")
    if artifact.get("schema") != SCHEMA:
        raise ProviderError("artifact.schema must be %r" % SCHEMA)
    kind = artifact.get("kind")
    if kind not in ("paint_batch", "gp_strokes", "flow_curves"):
        raise ProviderError("artifact.kind %r is not a v1 kind" % (kind,))
    if not isinstance(artifact.get("id"), str) or not artifact["id"]:
        raise ProviderError("artifact.id must be a non-empty string")
    target = artifact.get("target")
    if not isinstance(target, dict):
        raise ProviderError("artifact.target must be an object")
    if kind == "paint_batch":
        if not isinstance(target.get("image"), str) or not target["image"]:
            raise ProviderError("paint_batch target.image is required")
        _check_brush(artifact.get("brush"))
    else:
        if "brush" in artifact:
            raise ProviderError("%s artifacts carry no brush" % kind)
        if kind == "gp_strokes":
            for field in ("object", "layer"):
                if not isinstance(target.get(field), str) or not target[field]:
                    raise ProviderError("gp_strokes target.%s is required" % field)
            frame = target.get("frame")
            if not isinstance(frame, int) or isinstance(frame, bool) or frame < 0:
                raise ProviderError(
                    "gp_strokes target.frame must be a non-negative integer")
        else:
            if not isinstance(target.get("region"), str) or not target["region"]:
                raise ProviderError("flow_curves target.region is required")
    strokes = artifact.get("strokes")
    if not isinstance(strokes, list) or not strokes:
        raise ProviderError("artifact.strokes must be a non-empty array")
    if len(strokes) > MAX_STROKES:
        raise ProviderError(
            "artifact holds %d strokes; the bound is %d (refused, never truncated)"
            % (len(strokes), MAX_STROKES)
        )
    dim = 2 if kind == "paint_batch" else 3
    total = 0
    for s_index, stroke in enumerate(strokes):
        points = stroke.get("points") if isinstance(stroke, dict) else None
        if not isinstance(points, list) or not points:
            raise ProviderError("stroke %d must hold a non-empty points array" % s_index)
        if len(points) > MAX_POINTS_PER_STROKE:
            raise ProviderError(
                "stroke %d holds %d points; the bound is %d"
                % (s_index, len(points), MAX_POINTS_PER_STROKE)
            )
        total += len(points)
        if total > MAX_POINTS_TOTAL:
            raise ProviderError(
                "artifact exceeds the %d-point total bound" % MAX_POINTS_TOTAL
            )
        colour = stroke.get("colour")
        if colour is not None:
            _check_colour(colour, "stroke %d colour" % s_index)
        for p_index, point in enumerate(points):
            where = "stroke %d point %d" % (s_index, p_index)
            coords = point.get("p") if isinstance(point, dict) else None
            if not isinstance(coords, list) or len(coords) != dim:
                raise ProviderError("%s.p must hold %d coordinates" % (where, dim))
            for axis in coords:
                dec(axis, "%s.p" % where)
            dec(point.get("pressure"), "%s.pressure" % where)
            dec(point.get("radius"), "%s.radius" % where)
    claimed = artifact.get("sha256")
    actual = content_hash(artifact)
    if claimed != actual:
        raise ProviderError(
            "artifact content hash mismatch: claimed %r, computed %r"
            % (claimed, actual)
        )
    return kind, {"sha256": actual, "strokes": len(strokes), "points": total}


def _check_colour(colour, what):
    if not isinstance(colour, list) or len(colour) != 4:
        raise ProviderError("%s must be [r, g, b, a]" % what)
    for entry in colour:
        if not isinstance(entry, (int, float)) or not (0.0 <= float(entry) <= 1.0):
            raise ProviderError("%s entries must be numbers within 0.0..=1.0" % what)


def _check_brush(brush):
    if not isinstance(brush, dict):
        raise ProviderError("paint_batch requires a brush object")
    _check_colour(brush.get("colour"), "brush.colour")
    radius = brush.get("radius_px")
    if not isinstance(radius, int) or isinstance(radius, bool) or not (1 <= radius <= 512):
        raise ProviderError("brush.radius_px must be an integer within 1..=512")
    if brush.get("falloff") not in ("smooth", "constant"):
        raise ProviderError("brush.falloff must be smooth | constant")
    if brush.get("blend") not in ("mix", "alpha_over"):
        raise ProviderError("brush.blend must be mix | alpha_over")
    spacing = brush.get("spacing")
    if not isinstance(spacing, (int, float)) or not (0.0 < float(spacing) <= 10.0):
        raise ProviderError("brush.spacing must be a number within (0, 10]")
    opacity = brush.get("opacity")
    if not isinstance(opacity, (int, float)) or not (0.0 <= float(opacity) <= 1.0):
        raise ProviderError("brush.opacity must be a number within 0.0..=1.0")


# ---------------------------------------------------------------------------
# Paint rasterizer (D3): the provider owns the pixels. Walks each
# stroke's polyline in pixel space, stamps round dabs at a fixed
# spacing derived from the brush, composites into the image's
# float buffer. Pure arithmetic over the inputs — the same batch
# on the same image always yields the same pixels.
#
# Pixel mapping: UV (0,0) is the image's bottom-left; the pixel
# buffer is row-major from the bottom row, so pixel (x, y) sits
# at buffer offset (y * width + x) * 4 and its centre is at
# UV ((x + 0.5) / width, (y + 0.5) / height). Dab centres are
# computed in "pixel-centre coordinates" X = u * width - 0.5.
# ---------------------------------------------------------------------------

def rasterize_paint(image, artifact):
    width, height = image.size
    if width == 0 or height == 0:
        raise ProviderError("target image %r has no pixels" % image.name)
    brush = artifact["brush"]
    base_colour = [float(c) for c in brush["colour"]]
    radius_px = float(brush["radius_px"])
    spacing = float(brush["spacing"])
    opacity = float(brush["opacity"])
    falloff = brush["falloff"]
    blend = brush["blend"]
    step = max(0.25, spacing * radius_px)

    pixels = [0.0] * (width * height * 4)
    image.pixels.foreach_get(pixels)

    for stroke in artifact["strokes"]:
        colour = stroke.get("colour")
        rgba = [float(c) for c in colour] if colour is not None else base_colour
        points = []
        for point in stroke["points"]:
            u = dec(point["p"][0], "p.u")
            v = dec(point["p"][1], "p.v")
            points.append((
                u * width - 0.5,
                v * height - 0.5,
                dec(point["pressure"], "pressure"),
                dec(point["radius"], "radius"),
            ))
        _paint_stroke(pixels, width, height, points, rgba, radius_px, step,
                      opacity, falloff, blend)

    image.pixels.foreach_set(pixels)
    image.update()
    return {"image": image.name, "width": width, "height": height,
            "strokes": len(artifact["strokes"])}


def _paint_stroke(pixels, width, height, points, rgba, radius_px, step,
                  opacity, falloff, blend):
    if len(points) == 1:
        x, y, pressure, radius = points[0]
        _dab(pixels, width, height, x, y, radius_px * radius,
             rgba, opacity * pressure, falloff, blend)
        return
    carry = 0.0
    for index in range(len(points) - 1):
        x0, y0, p0, r0 = points[index]
        x1, y1, p1, r1 = points[index + 1]
        length = math.hypot(x1 - x0, y1 - y0)
        if length == 0.0:
            continue
        distance = -carry
        while distance <= length:
            t = max(distance, 0.0) / length
            _dab(
                pixels, width, height,
                x0 + (x1 - x0) * t,
                y0 + (y1 - y0) * t,
                radius_px * (r0 + (r1 - r0) * t),
                rgba,
                opacity * (p0 + (p1 - p0) * t),
                falloff, blend,
            )
            distance += step
        carry = distance - length


def _dab(pixels, width, height, cx, cy, radius, rgba, strength, falloff, blend):
    if radius <= 0.0 or strength <= 0.0:
        return
    x_lo = max(int(math.floor(cx - radius)), 0)
    x_hi = min(int(math.ceil(cx + radius)), width - 1)
    y_lo = max(int(math.floor(cy - radius)), 0)
    y_hi = min(int(math.ceil(cy + radius)), height - 1)
    src_r, src_g, src_b, src_a = rgba
    for y in range(y_lo, y_hi + 1):
        for x in range(x_lo, x_hi + 1):
            d = math.hypot(x - cx, y - cy) / radius
            if d > 1.0:
                continue
            if falloff == "smooth":
                weight = 0.5 + 0.5 * math.cos(math.pi * d)
            else:  # constant
                weight = 1.0
            alpha = strength * src_a * weight
            if alpha <= 0.0:
                continue
            offset = (y * width + x) * 4
            if blend == "mix":
                keep = 1.0 - alpha
                pixels[offset] = src_r * alpha + pixels[offset] * keep
                pixels[offset + 1] = src_g * alpha + pixels[offset + 1] * keep
                pixels[offset + 2] = src_b * alpha + pixels[offset + 2] * keep
                pixels[offset + 3] = src_a * alpha + pixels[offset + 3] * keep
            else:  # alpha_over (source-over)
                dst_a = pixels[offset + 3]
                out_a = alpha + dst_a * (1.0 - alpha)
                if out_a <= 0.0:
                    continue
                dst_keep = dst_a * (1.0 - alpha) / out_a
                src_take = alpha / out_a
                pixels[offset] = src_r * src_take + pixels[offset] * dst_keep
                pixels[offset + 1] = src_g * src_take + pixels[offset + 1] * dst_keep
                pixels[offset + 2] = src_b * src_take + pixels[offset + 2] * dst_keep
                pixels[offset + 3] = out_a


# ---------------------------------------------------------------------------
# Shell conversion (DESIGN §2.4): fixed arc-length resample,
# parallel-transport frames (never Frenet), diamond cross-section
# closed by construction, UVs mapped onto the atlas tile exactly.
# ---------------------------------------------------------------------------

def _shell_params(params):
    if not isinstance(params, dict):
        raise ProviderError("shell params must be an object", INVALID_PARAMS)
    tile = params.get("atlas_tile")
    if not isinstance(tile, dict) or not isinstance(tile.get("atlas_image"), str):
        raise ProviderError("params.atlas_tile.atlas_image is required", INVALID_PARAMS)
    uv_rect = tile.get("uv_rect")
    if not isinstance(uv_rect, list) or len(uv_rect) != 4:
        raise ProviderError("params.atlas_tile.uv_rect must be [u0, v0, u1, v1]",
                            INVALID_PARAMS)
    return {
        "width_root": dec(params.get("width_root"), "params.width_root"),
        "width_tip": dec(params.get("width_tip"), "params.width_tip"),
        "thickness": dec(params.get("thickness"), "params.thickness"),
        "segments_per_point": _int_param(params, "segments_per_point", 1, 64),
        "atlas_image": tile["atlas_image"],
        "uv_rect": [dec(v, "params.atlas_tile.uv_rect") for v in uv_rect],
        "chain": params.get("chain") if isinstance(params.get("chain"), str) else "",
        "mirror_of": params.get("mirror_of"),
    }


def _int_param(params, name, lo, hi):
    value = params.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or not (lo <= value <= hi):
        raise ProviderError(
            "params.%s must be an integer within %d..=%d" % (name, lo, hi),
            INVALID_PARAMS,
        )
    return value


def _resample(centres, segments_per_point):
    """Uniform arc-length resample: (n-1)*spp + 1 samples."""
    rings = (len(centres) - 1) * segments_per_point + 1
    lengths = [0.0]
    for index in range(1, len(centres)):
        lengths.append(lengths[-1] + (centres[index] - centres[index - 1]).length)
    total = lengths[-1]
    if total <= 0.0:
        raise ProviderError("centreline has zero length")
    samples = []
    segment = 1
    for ring in range(rings):
        target = total * ring / (rings - 1) if rings > 1 else 0.0
        while segment < len(lengths) - 1 and lengths[segment] < target:
            segment += 1
        seg_len = lengths[segment] - lengths[segment - 1]
        t = 0.0 if seg_len == 0.0 else (target - lengths[segment - 1]) / seg_len
        samples.append(centres[segment - 1].lerp(centres[segment], t))
    return samples, total


def _transport_frames(samples):
    """Parallel-transport frames: (tangent, normal, binormal) per
    sample. The initial normal is the unit axis least aligned
    with the first tangent, orthogonalized — fixed arithmetic,
    no view or time input."""
    tangents = []
    for index, point in enumerate(samples):
        if index == 0:
            delta = samples[1] - samples[0]
        elif index == len(samples) - 1:
            delta = samples[-1] - samples[-2]
        else:
            delta = samples[index + 1] - samples[index - 1]
        tangents.append(delta.normalized())
    axis = min(
        (Vector((1.0, 0.0, 0.0)), Vector((0.0, 1.0, 0.0)), Vector((0.0, 0.0, 1.0))),
        key=lambda candidate: abs(candidate.dot(tangents[0])),
    )
    normal = (axis - tangents[0] * axis.dot(tangents[0])).normalized()
    frames = []
    for index, tangent in enumerate(tangents):
        if index:
            rotation = tangents[index - 1].rotation_difference(tangent)
            normal = (rotation @ normal).normalized()
            # Re-orthogonalize against accumulated drift.
            normal = (normal - tangent * normal.dot(tangent)).normalized()
        frames.append((tangent, normal, tangent.cross(normal).normalized()))
    return frames


def build_shell(name, centres, params, width_scale=1.0):
    """Sweeps one closed shell along `centres`; returns the new
    object's name. Pure function of (centres, params)."""
    samples, total = _resample(centres, params["segments_per_point"])
    frames = _transport_frames(samples)
    u0, v0, u1, v1 = params["uv_rect"]
    verts = []
    uvs = []
    ring_count = len(samples)
    for index, (centre, (_, normal, binormal)) in enumerate(zip(samples, frames)):
        t = index / (ring_count - 1) if ring_count > 1 else 0.0
        half_width = 0.5 * (
            params["width_root"] + (params["width_tip"] - params["width_root"]) * t
        ) * width_scale
        half_thick = 0.5 * params["thickness"] * width_scale
        # Diamond section: +N, +B, -N, -B around the centre.
        section = [
            centre + normal * half_width,
            centre + binormal * half_thick,
            centre - normal * half_width,
            centre - binormal * half_thick,
        ]
        verts.extend(tuple(point) for point in section)
        u = u0 + (u1 - u0) * t
        for frac in (0.0, 1.0 / 3.0, 2.0 / 3.0, 1.0):
            uvs.append((u, v0 + (v1 - v0) * frac))
    faces = []
    for index in range(ring_count - 1):
        base = index * 4
        nxt = base + 4
        for side in range(4):
            faces.append((base + side, base + (side + 1) % 4,
                          nxt + (side + 1) % 4, nxt + side))
    # Caps: fans to the two centre points (closed by construction).
    root_centre = len(verts)
    verts.append(tuple(samples[0]))
    uvs.append((u0, (v0 + v1) / 2.0))
    tip_centre = len(verts)
    verts.append(tuple(samples[-1]))
    uvs.append((u1, (v0 + v1) / 2.0))
    last = (ring_count - 1) * 4
    for side in range(4):
        faces.append((root_centre, (side + 1) % 4, side))
        faces.append((tip_centre, last + side, last + (side + 1) % 4))

    mesh = bpy.data.meshes.new(name + "Mesh")
    mesh.from_pydata(verts, [], faces)
    mesh.update()
    uv_layer = mesh.uv_layers.new(name="UVMap")
    for loop in mesh.loops:
        uv_layer.data[loop.index].uv = uvs[loop.vertex_index]
    obj = bpy.data.objects.new(name, mesh)
    bpy.context.scene.collection.objects.link(obj)
    if params["chain"]:
        root_group = obj.vertex_groups.new(name=params["chain"])
        tip_group = obj.vertex_groups.new(name=params["chain"] + "_tip")
        for index in range(ring_count):
            t = index / (ring_count - 1) if ring_count > 1 else 0.0
            members = [index * 4 + side for side in range(4)]
            root_group.add(members, 1.0 - t, "REPLACE")
            tip_group.add(members, t, "REPLACE")
    material = _shell_material(params["atlas_image"])
    if material is not None:
        mesh.materials.append(material)
    return obj.name


def _shell_material(atlas_image):
    name = "Shell_" + atlas_image
    material = bpy.data.materials.get(name)
    if material is not None:
        return material
    image = bpy.data.images.get(atlas_image)
    if image is None:
        return None
    material = bpy.data.materials.new(name)
    material.use_nodes = True
    nodes = material.node_tree.nodes
    links = material.node_tree.links
    texture = nodes.new("ShaderNodeTexImage")
    texture.image = image
    principled = nodes.get("Principled BSDF")
    if principled is not None:
        links.new(texture.outputs["Color"], principled.inputs["Base Color"])
        links.new(texture.outputs["Alpha"], principled.inputs["Alpha"])
    return material


def _stroke_centres(stroke):
    centres = []
    for point in stroke["points"]:
        coords = [dec(axis, "p") for axis in point["p"]]
        centres.append(Vector(coords))
    if len(centres) < 2:
        raise ProviderError("a shell centreline needs at least two points")
    return centres


# ---------------------------------------------------------------------------
# Grease Pencil capture / replay (data-native, DESIGN §3).
# GPv3 layout: object.data (GreasePencilv3) -> layers -> frames
# -> drawing.strokes -> points (position / radius / opacity).
# Per-stroke colour rides the point "vertex_color" attribute
# when present and uniform; replay writes it back, so a
# capture -> replay -> capture round-trips to the same hash.
# ---------------------------------------------------------------------------

GP_FRAME = 1


def capture_gp(object_name):
    obj = bpy.data.objects.get(object_name)
    if obj is None or obj.type != "GREASEPENCIL":
        raise ProviderError("no Grease Pencil object named %r" % object_name)
    data = obj.data
    strokes_out = []
    layer_name = ""
    for layer in data.layers:
        for frame in layer.frames:
            drawing = frame.drawing
            if drawing is None:
                continue
            layer_name = layer.name
            colour_attr = None
            attrs = getattr(drawing, "attributes", None)
            if attrs is not None and "vertex_color" in attrs:
                colour_attr = attrs["vertex_color"]
            for s_index, stroke in enumerate(drawing.strokes):
                points_out = []
                colours = []
                for point in stroke.points:
                    pos = point.position
                    points_out.append({
                        "p": [fmt6(pos.x), fmt6(pos.y), fmt6(pos.z)],
                        "pressure": fmt6(point.opacity),
                        "radius": fmt6(point.radius),
                    })
                    if colour_attr is not None:
                        entry = colour_attr.data[
                            _point_offset(drawing, s_index) + len(points_out) - 1
                        ]
                        colours.append(tuple(entry.color))
                entry = {"points": points_out}
                if colours and all(c == colours[0] for c in colours):
                    entry["colour"] = [float(c) for c in colours[0]]
                strokes_out.append(entry)
    if not strokes_out:
        raise ProviderError("Grease Pencil object %r holds no strokes" % object_name)
    artifact = {
        "schema": SCHEMA,
        "kind": "gp_strokes",
        "id": "capture-" + object_name,
        "created_by": PROVIDER_NAME + " " + PROVIDER_VERSION,
        "target": {"object": object_name, "layer": layer_name or "Layer",
                   "frame": GP_FRAME},
        "strokes": strokes_out,
    }
    artifact["sha256"] = content_hash(artifact)
    return {"artifact": artifact}


def _point_offset(drawing, stroke_index):
    offset = 0
    for index, stroke in enumerate(drawing.strokes):
        if index == stroke_index:
            return offset
        offset += len(stroke.points)
    return offset


def replay_gp(artifact):
    target = artifact["target"]
    name = target["object"]
    existing = bpy.data.objects.get(name)
    if existing is not None:
        bpy.data.objects.remove(existing, do_unlink=True)
    data = bpy.data.grease_pencils.new(name)
    obj = bpy.data.objects.new(name, data)
    bpy.context.scene.collection.objects.link(obj)
    layer = data.layers.new(target["layer"], set_active=True)
    frame = layer.frames.new(GP_FRAME)
    drawing = frame.drawing
    counts = [len(stroke["points"]) for stroke in artifact["strokes"]]
    drawing.add_strokes(counts)
    colour_values = []
    have_colour = False
    for s_index, stroke in enumerate(artifact["strokes"]):
        gp_stroke = drawing.strokes[s_index]
        colour = stroke.get("colour")
        for p_index, point in enumerate(stroke["points"]):
            gp_point = gp_stroke.points[p_index]
            coords = [dec(axis, "p") for axis in point["p"]]
            gp_point.position = coords
            gp_point.opacity = dec(point["pressure"], "pressure")
            gp_point.radius = dec(point["radius"], "radius")
            if colour is not None:
                have_colour = True
                colour_values.append(tuple(float(c) for c in colour))
            else:
                colour_values.append((0.0, 0.0, 0.0, 1.0))
    if have_colour:
        attr = drawing.attributes.new("vertex_color", "FLOAT_COLOR", "POINT")
        for index, colour in enumerate(colour_values):
            attr.data[index].color = colour
    return {"object": obj.name, "strokes": len(counts)}


# ---------------------------------------------------------------------------
# Scene census: the estate digest (census2.py shape): per object,
# "%.6f %.6f %.6f" per point — shape-key data when keys exist,
# else vertex coordinates — objects name-sorted, hashed whole.
# ---------------------------------------------------------------------------

def scene_census():
    lines = []
    objects = []
    digest = hashlib.sha256()
    for obj in sorted(bpy.data.objects, key=lambda o: o.name):
        entry = {"name": obj.name, "type": obj.type}
        if obj.type == "MESH" and obj.data is not None:
            mesh = obj.data
            entry["vertices"] = len(mesh.vertices)
            entry["polygons"] = len(mesh.polygons)
            coords = []
            if mesh.shape_keys is not None and mesh.shape_keys.key_blocks:
                for block in mesh.shape_keys.key_blocks:
                    for point in block.data:
                        coords.append(point.co)
            else:
                for vertex in mesh.vertices:
                    coords.append(vertex.co)
            text = "".join("%.6f %.6f %.6f\n" % (c.x, c.y, c.z) for c in coords)
            entry["digest"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
            digest.update(text.encode("utf-8"))
            lines.append("%s %s" % (obj.name, entry["digest"]))
        objects.append(entry)
    return {"objects": objects, "digest": digest.hexdigest(),
            "scene": bpy.context.scene.name if bpy.context.scene else None}


# ---------------------------------------------------------------------------
# The twelve ops
# ---------------------------------------------------------------------------

class Provider:
    def __init__(self, secret):
        self.secret = secret
        self.session_id = None

    def initialize(self, params):
        self.session_id = uuid.uuid4().hex
        return {
            "session_id": self.session_id,
            "blender_version": ".".join(str(n) for n in bpy.app.version),
            "blender_version_full": bpy.app.version_string,
            "provider": PROVIDER_NAME,
            "provider_version": PROVIDER_VERSION,
        }

    def session_status(self, params):
        return {
            "blender_version": ".".join(str(n) for n in bpy.app.version),
            "blender_version_full": bpy.app.version_string,
            "provider": PROVIDER_NAME,
            "provider_version": PROVIDER_VERSION,
            "scene_open": bpy.data.filepath != "",
            "filepath": bpy.data.filepath,
            "objects": len(bpy.data.objects),
        }

    def scene_census(self, params):
        return scene_census()

    def gp_capture(self, params):
        object_name = params.get("object")
        if not isinstance(object_name, str) or not object_name:
            raise ProviderError("gp_capture requires an \"object\" name",
                                INVALID_PARAMS)
        return capture_gp(object_name)

    def artifact_validate(self, params):
        artifact = params.get("artifact")
        kind, info = validate_artifact(artifact)
        return {"valid": True, "kind": kind, **info}

    def gp_replay(self, params):
        artifact = params.get("artifact")
        kind, _ = validate_artifact(artifact)
        if kind != "gp_strokes":
            raise ProviderError("gp_replay needs a gp_strokes artifact")
        return replay_gp(artifact)

    def paint_apply(self, params):
        artifact = params.get("artifact")
        kind, _ = validate_artifact(artifact)
        if kind != "paint_batch":
            raise ProviderError("paint_apply needs a paint_batch artifact")
        image = bpy.data.images.get(artifact["target"]["image"])
        if image is None:
            raise ProviderError(
                "no image named %r in the session" % artifact["target"]["image"])
        return rasterize_paint(image, artifact)

    def stroke_to_shell(self, params):
        artifact = params.get("artifact")
        kind, _ = validate_artifact(artifact)
        if kind != "flow_curves":
            raise ProviderError("stroke_to_shell needs a flow_curves artifact")
        shell_params = _shell_params(params.get("params"))
        region = artifact["target"]["region"]
        built = []
        for index, stroke in enumerate(artifact["strokes"]):
            centres = _stroke_centres(stroke)
            if shell_params["mirror_of"]:
                centres = [Vector((-c.x, c.y, c.z)) for c in centres]
            built.append(build_shell(
                "%s_shell_%03d" % (region, index), centres, shell_params))
        return {"shells": built}

    def shells_along_flow(self, params):
        artifact = params.get("artifact")
        kind, _ = validate_artifact(artifact)
        if kind != "flow_curves":
            raise ProviderError("shells_along_flow needs a flow_curves artifact")
        raw = params.get("params")
        shell_params = _shell_params(raw)
        spacing = dec(raw.get("spacing_m"), "params.spacing_m")
        if spacing <= 0.0:
            raise ProviderError("params.spacing_m must be positive", INVALID_PARAMS)
        offsets = raw.get("layer_offsets") or ["0.000000"]
        if not isinstance(offsets, list) or not offsets:
            raise ProviderError("params.layer_offsets must be a non-empty array",
                                INVALID_PARAMS)
        lateral = [dec(entry, "params.layer_offsets") for entry in offsets]
        region = artifact["target"]["region"]
        built = []
        counter = 0
        for stroke in artifact["strokes"]:
            centres = _stroke_centres(stroke)
            # Fine uniform resample (8 per input segment): the
            # placement arithmetic and the frames both read it.
            samples, total = _resample(centres, 8)
            frames = _transport_frames(samples)
            last = len(samples) - 1
            root_index = 0
            root_distance = spacing
            while root_distance < total:
                # First sample at or past the root distance
                # (samples are arc-uniform, so arc position is
                # proportional to index).
                start_index = int(math.ceil(root_distance / total * last))
                sub = samples[start_index:]
                if len(sub) >= 2:
                    offset = lateral[root_index % len(lateral)]
                    if offset != 0.0:
                        normal = frames[start_index][1]
                        sub = [point + normal * offset for point in sub]
                    # Width tapers with root position along the
                    # flow (placement rule, DESIGN §1 op 8).
                    scale = 1.0 - 0.5 * (root_distance / total)
                    built.append(build_shell(
                        "%s_flow_%03d" % (region, counter), sub, shell_params,
                        width_scale=scale))
                    counter += 1
                root_index += 1
                root_distance += spacing
        return {"shells": built}

    def image_export_png(self, params):
        image_name = params.get("image")
        path = params.get("path")
        if not isinstance(image_name, str) or not isinstance(path, str):
            raise ProviderError("image_export_png requires image + path",
                                INVALID_PARAMS)
        image = bpy.data.images.get(image_name)
        if image is None:
            raise ProviderError("no image named %r" % image_name)
        previous_format = image.file_format
        previous_path = image.filepath_raw
        try:
            image.file_format = "PNG"
            image.filepath_raw = path
            image.save()
        finally:
            image.file_format = previous_format
            image.filepath_raw = previous_path
        return {"path": path, "bytes": os.path.getsize(path)}

    def proof_render(self, params):
        path = params.get("path")
        if not isinstance(path, str) or not path:
            raise ProviderError("proof_render requires a path", INVALID_PARAMS)
        scene = bpy.context.scene
        camera = params.get("camera")
        if isinstance(camera, str) and camera:
            cam_obj = bpy.data.objects.get(camera)
            if cam_obj is None:
                raise ProviderError("no camera object named %r" % camera)
            scene.camera = cam_obj
        if scene.camera is None:
            raise ProviderError("the scene has no camera")
        render = scene.render
        previous = (render.filepath, render.resolution_x, render.resolution_y,
                    render.image_settings.file_format)
        try:
            if isinstance(params.get("width"), int):
                render.resolution_x = params["width"]
            if isinstance(params.get("height"), int):
                render.resolution_y = params["height"]
            render.image_settings.file_format = "PNG"
            render.filepath = path
            bpy.ops.render.render(write_still=True)
        finally:
            (render.filepath, render.resolution_x, render.resolution_y,
             render.image_settings.file_format) = previous
        return {"path": path, "bytes": os.path.getsize(path)}

    def blend_save(self, params):
        path = params.get("path")
        if not isinstance(path, str) or not path.endswith(".blend"):
            raise ProviderError("blend_save requires an explicit .blend path",
                                INVALID_PARAMS)
        bpy.ops.wm.save_as_mainfile(filepath=path)
        return {"path": path, "bytes": os.path.getsize(path)}

    def scene_open(self, params):
        path = params.get("path")
        if not isinstance(path, str) or not path.endswith(".blend"):
            raise ProviderError("scene_open requires an explicit .blend path",
                                INVALID_PARAMS)
        if not os.path.isfile(path):
            raise ProviderError("no such file: %s" % path)
        bpy.ops.wm.open_mainfile(filepath=path)
        return {"opened": path, "objects": len(bpy.data.objects)}

    OPS = {
        "session_status": session_status,
        "scene_census": scene_census,
        "gp_capture": gp_capture,
        "artifact_validate": artifact_validate,
        "gp_replay": gp_replay,
        "paint_apply": paint_apply,
        "stroke_to_shell": stroke_to_shell,
        "shells_along_flow": shells_along_flow,
        "image_export_png": image_export_png,
        "proof_render": proof_render,
        "blend_save": blend_save,
        "scene_open": scene_open,
    }

    def dispatch(self, method, params):
        if method == "initialize":
            return self.initialize(params)
        handler = self.OPS.get(method)
        if handler is None:
            raise ProviderError("unknown provider method %r" % method,
                                INVALID_PARAMS)
        return handler(self, params if isinstance(params, dict) else {})


# ---------------------------------------------------------------------------
# HTTP transport: one server, main thread, loopback only. The
# provider secret is checked on every request (403 otherwise);
# after initialize, the session header must match (-32001).
# ---------------------------------------------------------------------------

def make_handler(provider):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):  # silence the access log
            pass

        def _reply(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.headers.get("X-Seahawk-Provider-Secret") != provider.secret:
                self._reply(403, {"error": "missing or wrong provider secret"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                frame = json.loads(self.rfile.read(length) or b"{}")
            except Exception as error:
                self._reply(400, {"error": "unparseable request: %s" % error})
                return
            call_id = frame.get("id")
            method = frame.get("method")
            params = frame.get("params") or {}
            if method != "initialize":
                if self.headers.get("X-Seahawk-Session-Id") != provider.session_id \
                        or provider.session_id is None:
                    self._reply(200, {
                        "jsonrpc": "2.0", "id": call_id,
                        "error": {"code": SESSION_INVALID,
                                  "message": "session invalid or not established"},
                    })
                    return
            try:
                result = provider.dispatch(method, params)
                self._reply(200, {"jsonrpc": "2.0", "id": call_id, "result": result})
            except ProviderError as error:
                self._reply(200, {
                    "jsonrpc": "2.0", "id": call_id,
                    "error": {"code": error.code, "message": str(error)},
                })
            except Exception as error:  # the provider answers, never hangs
                self._reply(200, {
                    "jsonrpc": "2.0", "id": call_id,
                    "error": {"code": PROVIDER_ERROR,
                              "message": "%s: %s" % (type(error).__name__, error)},
                })

    return Handler


def main():
    secret = os.environ.get("SEAHAWK_PROVIDER_SECRET", "")
    if not secret:
        print("FATAL: SEAHAWK_PROVIDER_SECRET is not set", file=sys.stderr)
        raise SystemExit(2)
    port = int(os.environ.get("SEAHAWK_PROVIDER_PORT", "8471"))
    provider = Provider(secret)
    server = HTTPServer(("127.0.0.1", port), make_handler(provider))
    print("OK %s listening on 127.0.0.1:%d (Blender %s)"
          % (PROVIDER_NAME, port, bpy.app.version_string))
    sys.stdout.flush()
    server.serve_forever()


main()
