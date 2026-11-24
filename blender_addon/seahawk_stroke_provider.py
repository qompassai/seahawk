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
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import bpy
from mathutils import Quaternion, Vector

PROVIDER_NAME = "seahawk-stroke-provider"
PROVIDER_VERSION = "1.1.0"
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
# Animation layer (DESIGN-ANIM): takes, poses, curves, GP frame
# ranges, bake, gated render. Mirrors the broker's validators
# (src/take.rs) rule for rule: canonical JSON, embedded SHA-256,
# 6-decimal-string numerics, bounds refused never truncated,
# the v2 excluded set refused by name. Capture is transcription
# (the API's own values, read verbatim); apply constructs
# keyframe points from data, never through Blender's
# interactive keying operators (DESIGN-ANIM §2.1).
# ---------------------------------------------------------------------------

TAKE_SCHEMA = "seahawk.take/v2"
POSE_SCHEMA = "seahawk.pose/v2"
TAKE_EXPORT_SCHEMA = "seahawk.take-export/v2"

MAX_CHANNELS = 4096
MAX_KEYS_PER_CHANNEL = 4096
MAX_KEYS_TOTAL = 1000000
MAX_FRAME_SPAN = 3600
MAX_GP_TRACKS = 64
MAX_GP_REFS_TOTAL = 3600
MAX_POSE_CHANNELS = 4096
MAX_ID_CHARS = 128
MAX_NAME_CHARS = 256

INTERPS = {
    "CONSTANT", "LINEAR", "BEZIER", "SINE", "QUAD", "CUBIC",
    "QUART", "QUINT", "EXPO", "CIRC", "BACK", "BOUNCE", "ELASTIC",
}
EASING_INTERPS = {
    "SINE", "QUAD", "CUBIC", "QUART", "QUINT", "EXPO", "CIRC", "BACK",
}
EASINGS = {"AUTO", "EASE_IN", "EASE_OUT", "EASE_IN_OUT"}
HANDLE_TYPES = {"AUTO_CLAMPED", "AUTO", "VECTOR", "ALIGNED", "FREE"}
EXTRAPOLATIONS = {"CONSTANT", "LINEAR"}
V2_EXCLUDED_KEYS = {
    "driver", "drivers", "fcurve_modifiers", "modifier", "modifiers", "nla",
}
_TRANSFORM_PROPS = {"location", "rotation_euler", "rotation_quaternion", "scale"}
_BONE_PATH = re.compile(r'^pose\.bones\["([^"]+)"\]\.(location|rotation_euler|rotation_quaternion|scale)$')
_KEY_PATH = re.compile(r'^key_blocks\["([^"]+)"\]\.value$')
_DEC6 = re.compile(r"^-?\d+\.\d{6}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# Session artifact store: GP drawings this provider captured
# (or was handed) this process, keyed by content hash. A take
# binds GP drawings by hash; take_apply resolves them here or
# from the call's own artifacts map, and refuses by hash when
# neither holds them (DESIGN-ANIM §1.3).
_ARTIFACT_STORE = {}


def _is_dec6(value):
    return isinstance(value, str) and _DEC6.match(value) is not None


def _is_sha256(value):
    return isinstance(value, str) and _SHA256_HEX.match(value) is not None


def _find_excluded_v2(value, in_bake_settings=False):
    if isinstance(value, dict):
        for key, child in value.items():
            if not in_bake_settings and (
                key in EXCLUDED_KEYS or key in V2_EXCLUDED_KEYS
            ):
                return key
            child_in_settings = (
                key == "settings"
                and "settings_sha256" in value
                and "system" in value
            )
            hit = _find_excluded_v2(child, in_bake_settings or child_in_settings)
            if hit is not None:
                return hit
    elif isinstance(value, list):
        for item in value:
            hit = _find_excluded_v2(item, in_bake_settings)
            if hit is not None:
                return hit
    return None


def _check_keys(obj, allowed, what):
    for key in obj.keys():
        if key not in allowed:
            raise ProviderError(
                "%s carries unknown key %r; the v2 schema admits only %s"
                % (what, key, sorted(allowed))
            )


def _required_string(obj, key, what, limit=MAX_NAME_CHARS):
    value = obj.get(key)
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ProviderError(
            "%s.%s must be a non-empty string of at most %d characters"
            % (what, key, limit)
        )
    return value


def _check_path(path, what):
    if path in _TRANSFORM_PROPS:
        return
    if _BONE_PATH.match(path) or _KEY_PATH.match(path):
        return
    raise ProviderError(
        "%s.path %r is not a v2 channel address (a bare transform "
        "property, pose.bones[\"<bone>\"].<property>, or "
        "key_blocks[\"<block>\"].value)" % (what, path)
    )


def _channel_address(channel):
    ident = channel["id"]
    return "%s:%s|%s|%d" % (ident["type"], ident["name"],
                            channel["path"], channel["index"])


def _check_handle_pair(key, field, what):
    value = key.get(field)
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) != 2
        or not all(_is_dec6(part) for part in value)
    ):
        raise ProviderError(
            "%s.%s must be null or [frame, value] as 6-decimal strings"
            % (what, field)
        )
    return value


def _check_handle_type(key, field, what):
    value = key.get(field)
    if value is None:
        return None
    if value not in HANDLE_TYPES:
        raise ProviderError(
            "%s.%s must be null or one of %s" % (what, field, sorted(HANDLE_TYPES))
        )
    return value


def _check_key(key, what):
    if not isinstance(key, dict):
        raise ProviderError("%s must be an object" % what)
    _check_keys(
        key,
        {"frame", "value", "interp", "easing", "handle_left", "handle_right",
         "handle_left_type", "handle_right_type", "back", "amplitude", "period"},
        what,
    )
    if not _is_dec6(key.get("frame")):
        raise ProviderError("%s.frame must be a 6-decimal string (D2)" % what)
    if not _is_dec6(key.get("value")):
        raise ProviderError("%s.value must be a 6-decimal string (D2)" % what)
    interp = key.get("interp")
    if interp not in INTERPS:
        raise ProviderError(
            "%s.interp %r is not in Blender's interpolation enum" % (what, interp))
    easing = key.get("easing")
    if easing is not None:
        if interp not in EASING_INTERPS:
            raise ProviderError(
                "%s.easing is set but interpolation %s does not read an "
                "easing mode" % (what, interp))
        if easing not in EASINGS:
            raise ProviderError(
                "%s.easing %r must be one of %s" % (what, easing, sorted(EASINGS)))
    elif interp in EASING_INTERPS:
        raise ProviderError(
            "%s.easing is required by interpolation %s" % (what, interp))
    handle_left = _check_handle_pair(key, "handle_left", what)
    handle_right = _check_handle_pair(key, "handle_right", what)
    handle_left_type = _check_handle_type(key, "handle_left_type", what)
    handle_right_type = _check_handle_type(key, "handle_right_type", what)
    if interp == "BEZIER":
        if (handle_left is None or handle_right is None
                or handle_left_type is None or handle_right_type is None):
            raise ProviderError(
                "%s is a BEZIER key without full handle data; handles are "
                "carried, never recomputed (DESIGN-ANIM §3)" % what)
    elif (handle_left is not None or handle_right is not None
            or handle_left_type is not None or handle_right_type is not None):
        raise ProviderError(
            "%s carries handle data but interpolation %s does not read "
            "handles" % (what, interp))
    for field, required in (
        ("back", interp == "BACK"),
        ("amplitude", interp == "ELASTIC"),
        ("period", interp == "ELASTIC"),
    ):
        value = key.get(field)
        if value is not None and not _is_dec6(value):
            raise ProviderError(
                "%s.%s must be null or a 6-decimal string" % (what, field))
        if required and value is None:
            raise ProviderError(
                "%s.%s is required by interpolation %s; a key that omits "
                "data evaluation would read is malformed" % (what, field, interp))
        if not required and value is not None:
            raise ProviderError(
                "%s.%s is set but interpolation %s does not read it"
                % (what, field, interp))
    return float(key["frame"])


def _check_channel_head(channel, what, with_extrapolation):
    if not isinstance(channel, dict):
        raise ProviderError("%s must be an object" % what)
    if with_extrapolation:
        allowed = {"id", "slot", "path", "index", "extrapolation", "keys"}
    else:
        allowed = {"id", "slot", "path", "index", "value", "handle_left",
                   "handle_right", "handle_left_type", "handle_right_type"}
    _check_keys(channel, allowed, what)
    ident = channel.get("id")
    if not isinstance(ident, dict):
        raise ProviderError("%s.id must be an object" % what)
    _check_keys(ident, {"type", "name"}, "%s.id" % what)
    _required_string(ident, "type", "%s.id" % what)
    _required_string(ident, "name", "%s.id" % what)
    slot = channel.get("slot")
    if slot is not None and (not isinstance(slot, str) or not slot):
        raise ProviderError("%s.slot must be null or a non-empty string" % what)
    _check_path(_required_string(channel, "path", what), what)
    index = channel.get("index")
    if not isinstance(index, int) or isinstance(index, bool) or not (0 <= index <= 3):
        raise ProviderError("%s.index must be an integer within 0..=3" % what)
    if with_extrapolation and channel.get("extrapolation") not in EXTRAPOLATIONS:
        raise ProviderError(
            "%s.extrapolation must be CONSTANT | LINEAR" % what)
    return _channel_address(channel)


def _check_frames_block(frames, what):
    if not isinstance(frames, dict):
        raise ProviderError("%s must be an object" % what)
    _check_keys(frames, {"start", "end", "fps_num", "fps_base"}, what)
    start, end = frames.get("start"), frames.get("end")
    if (not isinstance(start, int) or isinstance(start, bool)
            or not isinstance(end, int) or isinstance(end, bool)
            or start < 0 or end < start):
        raise ProviderError(
            "%s.start and %s.end must be non-negative integers, end >= start"
            % (what, what))
    if end - start > MAX_FRAME_SPAN:
        raise ProviderError(
            "%s spans %d frames; the bound is %d (refused, not truncated)"
            % (what, end - start, MAX_FRAME_SPAN))
    fps_num = frames.get("fps_num")
    if not isinstance(fps_num, int) or isinstance(fps_num, bool) or fps_num < 1:
        raise ProviderError("%s.fps_num must be an integer >= 1" % what)
    if not _is_dec6(frames.get("fps_base")) or float(frames["fps_base"]) <= 0.0:
        raise ProviderError(
            "%s.fps_base must be a positive 6-decimal string" % what)
    return frames


def _check_scene_target(envelope, what, target_keys):
    target = envelope.get("target")
    if not isinstance(target, dict):
        raise ProviderError("%s.target must be an object" % what)
    _check_keys(target, target_keys, "%s.target" % what)
    if not _is_sha256(target.get("scene_sha256")):
        raise ProviderError(
            "%s.target.scene_sha256 must be 64 lowercase hex characters "
            "(the scene-hash binding, DESIGN-ANIM §1.1)" % what)
    return target


def _check_envelope_hash(envelope, what):
    claimed = envelope.get("sha256")
    if not _is_sha256(claimed):
        raise ProviderError(
            "%s.sha256 is required (64 lowercase hex, over the canonical "
            "bytes)" % what)
    actual = content_hash(envelope)
    if claimed != actual:
        raise ProviderError(
            "%s.sha256 does not match the canonical content hash (claimed "
            "%s, computed %s); the artifact is refused, not repaired"
            % (what, claimed, actual))


def validate_take(envelope):
    """Mirror of src/take.rs validate_take: returns an info dict."""
    if not isinstance(envelope, dict):
        raise ProviderError("take must be a JSON object")
    excluded = _find_excluded_v2(envelope)
    if excluded is not None:
        raise ProviderError(
            "take carries excluded construct %r: drivers, NLA, F-curve "
            "modifiers, and the v1 interactive-engine features are "
            "policy-excluded because a take must be self-contained key "
            "data (DESIGN-ANIM §3)" % excluded)
    _check_keys(
        envelope,
        {"schema", "id", "created_by", "target", "frames", "channels",
         "gp_tracks", "bake", "sha256"},
        "take",
    )
    if envelope.get("schema") != TAKE_SCHEMA:
        raise ProviderError("take.schema must be %r" % TAKE_SCHEMA)
    _required_string(envelope, "id", "take", MAX_ID_CHARS)
    if "created_by" in envelope and envelope["created_by"] is not None:
        if not isinstance(envelope["created_by"], str) \
                or len(envelope["created_by"]) > MAX_NAME_CHARS:
            raise ProviderError("take.created_by must be a short string")
    target = _check_scene_target(envelope, "take", {"scene_sha256", "rig"})
    rig = target.get("rig")
    if rig is not None and (not isinstance(rig, str) or not rig):
        raise ProviderError("take.target.rig must be null or a non-empty string")
    frames = _check_frames_block(envelope.get("frames"), "take.frames")
    channels = envelope.get("channels")
    if not isinstance(channels, list):
        raise ProviderError("take.channels must be an array")
    if len(channels) > MAX_CHANNELS:
        raise ProviderError(
            "take carries %d channels; the bound is %d (refused, not "
            "truncated)" % (len(channels), MAX_CHANNELS))
    addresses = set()
    total_keys = 0
    for index, channel in enumerate(channels):
        what = "take.channels[%d]" % index
        address = _check_channel_head(channel, what, True)
        if address in addresses:
            raise ProviderError(
                "take carries channel %s twice; two channels writing one "
                "address in one take is a refusal (DESIGN-ANIM §1.2)" % address)
        addresses.add(address)
        keys = channel.get("keys")
        if not isinstance(keys, list) or not keys:
            raise ProviderError("%s.keys must be a non-empty array" % what)
        if len(keys) > MAX_KEYS_PER_CHANNEL:
            raise ProviderError(
                "%s carries %d keys; the bound is %d (refused, not "
                "truncated)" % (what, len(keys), MAX_KEYS_PER_CHANNEL))
        total_keys += len(keys)
        if total_keys > MAX_KEYS_TOTAL:
            raise ProviderError(
                "take carries more than %d keys in total (refused, not "
                "truncated)" % MAX_KEYS_TOTAL)
        previous = None
        for key_index, key in enumerate(keys):
            key_what = "%s.keys[%d]" % (what, key_index)
            frame = _check_key(key, key_what)
            if frame < frames["start"] or frame > frames["end"]:
                raise ProviderError(
                    "%s.frame %s lies outside the take range %d..=%d; a "
                    "key outside the range is a refusal, not a clip "
                    "(DESIGN-ANIM §1.1)"
                    % (key_what, key["frame"], frames["start"], frames["end"]))
            if previous is not None and frame <= previous:
                raise ProviderError(
                    "%s.frame %s does not ascend past the previous key"
                    % (key_what, key["frame"]))
            previous = frame
    gp_tracks = envelope.get("gp_tracks")
    if not isinstance(gp_tracks, list):
        raise ProviderError(
            "take.gp_tracks is required (an empty array when the take "
            "has no GP)")
    if len(gp_tracks) > MAX_GP_TRACKS:
        raise ProviderError(
            "take carries %d GP tracks; the bound is %d (refused, not "
            "truncated)" % (len(gp_tracks), MAX_GP_TRACKS))
    total_refs = 0
    for index, track in enumerate(gp_tracks):
        what = "take.gp_tracks[%d]" % index
        if not isinstance(track, dict):
            raise ProviderError("%s must be an object" % what)
        _check_keys(track, {"object", "layer", "frames"}, what)
        _required_string(track, "object", what)
        _required_string(track, "layer", what)
        track_frames = track.get("frames")
        if not isinstance(track_frames, list) or not track_frames:
            raise ProviderError("%s.frames must be a non-empty array" % what)
        previous = None
        for ref_index, entry in enumerate(track_frames):
            entry_what = "%s.frames[%d]" % (what, ref_index)
            if not isinstance(entry, dict):
                raise ProviderError("%s must be an object" % entry_what)
            _check_keys(entry, {"frame", "artifact"}, entry_what)
            frame = entry.get("frame")
            if not isinstance(frame, int) or isinstance(frame, bool) or frame < 0:
                raise ProviderError(
                    "%s.frame must be a non-negative integer" % entry_what)
            if frame < frames["start"] or frame > frames["end"]:
                raise ProviderError(
                    "%s.frame %d lies outside the take range %d..=%d"
                    % (entry_what, frame, frames["start"], frames["end"]))
            if previous is not None and frame <= previous:
                raise ProviderError(
                    "%s.frame %d does not ascend" % (entry_what, frame))
            previous = frame
            if not _is_sha256(entry.get("artifact")):
                raise ProviderError(
                    "%s.artifact must be the 64-hex content hash of a v1 "
                    "gp_strokes artifact (DESIGN-ANIM §1.3)" % entry_what)
        total_refs += len(track_frames)
        if total_refs > MAX_GP_REFS_TOTAL:
            raise ProviderError(
                "take carries more than %d GP frame references (refused, "
                "not truncated)" % MAX_GP_REFS_TOTAL)
    bake = envelope.get("bake")
    baked = False
    if bake is not None:
        baked = True
        if not isinstance(bake, dict):
            raise ProviderError("take.bake must be null or an object")
        _check_keys(
            bake,
            {"system", "blender", "frames", "settings", "settings_sha256",
             "channels", "evidence"},
            "take.bake",
        )
        _required_string(bake, "system", "take.bake")
        _required_string(bake, "blender", "take.bake")
        _required_string(bake, "evidence", "take.bake")
        bake_frames = _check_frames_block(bake.get("frames"), "take.bake.frames")
        if (bake_frames["start"] != frames["start"]
                or bake_frames["end"] != frames["end"]
                or bake_frames["fps_num"] != frames["fps_num"]
                or bake_frames["fps_base"] != frames["fps_base"]):
            raise ProviderError(
                "take.bake.frames must equal the take's frame block "
                "(DESIGN-ANIM §4.2)")
        settings = bake.get("settings")
        if not isinstance(settings, dict):
            raise ProviderError("take.bake.settings must be an object")
        settings_hash = hashlib.sha256(canonical_bytes(settings)).hexdigest()
        if bake.get("settings_sha256") != settings_hash:
            raise ProviderError(
                "take.bake.settings_sha256 does not match the settings "
                "content hash (computed %s); a bake whose settings are "
                "not recorded exactly is a rumour (DESIGN-ANIM §4.2)"
                % settings_hash)
        baked_channels = bake.get("channels")
        if not isinstance(baked_channels, list) or not baked_channels:
            raise ProviderError(
                "take.bake.channels must name at least one baked channel")
        for entry in baked_channels:
            if not isinstance(entry, str) or entry not in addresses:
                raise ProviderError(
                    "take.bake.channels names %r, which is not a channel "
                    "of this take" % (entry,))
    _check_envelope_hash(envelope, "take")
    return {
        "id": envelope["id"],
        "sha256": envelope["sha256"],
        "channels": len(channels),
        "keys": total_keys,
        "gp_tracks": len(gp_tracks),
        "gp_refs": total_refs,
        "baked": baked,
    }


def validate_pose(envelope):
    """Mirror of src/take.rs validate_pose: returns an info dict."""
    if not isinstance(envelope, dict):
        raise ProviderError("pose must be a JSON object")
    excluded = _find_excluded_v2(envelope)
    if excluded is not None:
        raise ProviderError(
            "pose carries excluded construct %r (DESIGN-ANIM §3)" % excluded)
    _check_keys(
        envelope,
        {"schema", "id", "created_by", "target", "frame", "channels",
         "insert", "sha256"},
        "pose",
    )
    if envelope.get("schema") != POSE_SCHEMA:
        raise ProviderError("pose.schema must be %r" % POSE_SCHEMA)
    _required_string(envelope, "id", "pose", MAX_ID_CHARS)
    _check_scene_target(envelope, "pose", {"scene_sha256"})
    frame = envelope.get("frame")
    if not isinstance(frame, int) or isinstance(frame, bool) or frame < 0:
        raise ProviderError("pose.frame must be a non-negative integer")
    insert = envelope.get("insert")
    if not isinstance(insert, dict):
        raise ProviderError("pose.insert must be an object")
    _check_keys(insert, {"interp"}, "pose.insert")
    insert_interp = insert.get("interp")
    if insert_interp not in ("CONSTANT", "LINEAR", "BEZIER"):
        raise ProviderError(
            "pose.insert.interp must be CONSTANT | LINEAR | BEZIER")
    channels = envelope.get("channels")
    if not isinstance(channels, list) or not channels:
        raise ProviderError("pose.channels must be a non-empty array")
    if len(channels) > MAX_POSE_CHANNELS:
        raise ProviderError(
            "pose carries %d channels; the bound is %d (refused, not "
            "truncated)" % (len(channels), MAX_POSE_CHANNELS))
    addresses = set()
    for index, channel in enumerate(channels):
        what = "pose.channels[%d]" % index
        address = _check_channel_head(channel, what, False)
        if address in addresses:
            raise ProviderError("pose carries channel %s twice" % address)
        addresses.add(address)
        if not _is_dec6(channel.get("value")):
            raise ProviderError(
                "%s.value must be a 6-decimal string (D2)" % what)
        handle_left = _check_handle_pair(channel, "handle_left", what)
        handle_right = _check_handle_pair(channel, "handle_right", what)
        handle_left_type = _check_handle_type(channel, "handle_left_type", what)
        handle_right_type = _check_handle_type(channel, "handle_right_type", what)
        has_handles = (handle_left is not None and handle_right is not None
                       and handle_left_type is not None
                       and handle_right_type is not None)
        if insert_interp == "BEZIER" and not has_handles:
            raise ProviderError(
                "%s carries no handles, but pose.insert.interp is BEZIER; "
                "a BEZIER insert is admissible only if the pose carries "
                "handles per channel (DESIGN-ANIM §1.4)" % what)
        if insert_interp != "BEZIER" and (
            handle_left is not None or handle_right is not None
            or handle_left_type is not None or handle_right_type is not None
        ):
            raise ProviderError(
                "%s carries handle data, but pose.insert.interp is %s"
                % (what, insert_interp))
    _check_envelope_hash(envelope, "pose")
    return {"id": envelope["id"], "sha256": envelope["sha256"],
            "channels": len(channels)}


def action_digest(take):
    """Mirror of src/take.rs action_digest (DESIGN-ANIM §6.1)."""
    lines = []
    for channel in take["channels"]:
        ident = channel["id"]
        lines.append("C|%s|%s|%s|%s|%d|%s" % (
            ident["type"], ident["name"], channel.get("slot") or "",
            channel["path"], channel["index"], channel["extrapolation"]))
        for key in channel["keys"]:
            def text(field):
                value = key.get(field)
                return value if isinstance(value, str) else ""

            def pair(field):
                value = key.get(field)
                if isinstance(value, list) and len(value) == 2:
                    return "%s,%s" % (value[0], value[1])
                return ""

            lines.append("K|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                text("frame"), text("value"), text("interp"), text("easing"),
                pair("handle_left"), pair("handle_right"),
                text("handle_left_type"), text("handle_right_type"),
                text("back"), text("amplitude"), text("period")))
    payload = "".join(line + "\n" for line in lines)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Animation scene machinery
# ---------------------------------------------------------------------------

def _scene_sha256():
    path = bpy.data.filepath
    if not path or not os.path.isfile(path):
        raise ProviderError(
            "no scene file is open in the session; the scene-hash "
            "binding cannot be established")
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _check_scene_binding(claimed):
    current = _scene_sha256()
    if claimed != current:
        raise ProviderError(
            "the artifact is bound to scene %s but the open scene "
            "hashes to %s; refused before mutation (stale scene "
            "hash, DESIGN-ANIM §1.1)" % (claimed, current))


def _fps_block():
    scene = bpy.context.scene
    return {
        "fps_num": scene.render.fps,
        "fps_base": fmt6(scene.render.fps_base),
    }


def _check_anim_exclusions(adt, label):
    if adt is None:
        return
    if len(adt.drivers) > 0:
        raise ProviderError(
            "drivers on %s: a take must be self-contained key data "
            "and drivers are evaluation-time state outside the key "
            "set (DESIGN-ANIM §3); capture refuses" % label)
    for track in adt.nla_tracks:
        if len(track.strips) > 0:
            raise ProviderError(
                "NLA track %r on %s: NLA is evaluation-time state "
                "outside the key set (DESIGN-ANIM §3); capture "
                "refuses" % (track.name, label))


def _read_slot(adt, label):
    action = adt.action
    slot = adt.action_slot
    if slot is not None:
        return slot
    if len(action.slots) == 1:
        return action.slots[0]
    if len(action.slots) > 1:
        raise ProviderError(
            "the action on %s binds %d slots and none is assigned; "
            "capture cannot attribute its channels" % (label, len(action.slots)))
    return None


def _fcurves_for_read(adt, label):
    """(slot, fcurve collection) for the owner's bound action,
    with the layered-action exclusions enforced by name."""
    action = adt.action
    if action is None:
        return None, []
    slot = _read_slot(adt, label)
    if len(action.layers) == 0:
        return slot, action.fcurves
    strips = [
        strip
        for layer in action.layers
        for strip in layer.strips
        if strip.type == "KEYFRAME"
    ]
    if len(strips) > 1:
        raise ProviderError(
            "multi-strip layered action on %s: %d keyframe strips; "
            "v2 carries one strip per slot (DESIGN-ANIM §3); "
            "capture refuses" % (label, len(strips)))
    if not strips:
        return slot, []
    if slot is None:
        raise ProviderError(
            "the layered action on %s has no resolvable slot; "
            "capture refuses" % label)
    bag = strips[0].channelbag(slot)
    return slot, (bag.fcurves if bag is not None else [])


def _fcurves_for_write(owner, id_type, id_name, action_name):
    """The fcurve collection to write into: a fresh named action
    (replace semantics) when action_name is given, else the
    owner's current action, created on first use."""
    adt = owner.animation_data
    if adt is None:
        adt = owner.animation_data_create()
    if action_name is not None:
        existing = bpy.data.actions.get(action_name)
        if existing is not None:
            bpy.data.actions.remove(existing)
        action = bpy.data.actions.new(action_name)
        slot = action.slots.new(id_type, id_name)
        layer = action.layers.new("Layer")
        strip = layer.strips.new(type="KEYFRAME")
        bag = strip.channelbags.new(slot)
        adt.action = action
        adt.action_slot = slot
        return bag.fcurves
    action = adt.action
    if action is None:
        return _fcurves_for_write(
            owner, id_type, id_name, "Seahawk_" + id_name)
    slot = adt.action_slot
    if slot is None:
        if len(action.slots) == 1:
            slot = action.slots[0]
        elif len(action.slots) == 0:
            slot = action.slots.new(id_type, id_name)
        else:
            raise ProviderError(
                "the action on %s binds %d slots and none is "
                "assigned; apply cannot attribute its channels"
                % (id_name, len(action.slots)))
        adt.action_slot = slot
    if len(action.layers) == 0:
        return action.fcurves
    strips = [
        strip
        for layer in action.layers
        for strip in layer.strips
        if strip.type == "KEYFRAME"
    ]
    if len(strips) > 1:
        raise ProviderError(
            "multi-strip layered action on %s: v2 writes one strip "
            "per slot (DESIGN-ANIM §3); apply refuses" % id_name)
    if strips:
        bag = strips[0].channelbag(slot)
        if bag is None:
            bag = strips[0].channelbags.new(slot)
        return bag.fcurves
    layer = action.layers.new("Layer")
    strip = layer.strips.new(type="KEYFRAME")
    return strip.channelbags.new(slot).fcurves


def _resolve_owner(id_type, id_name):
    if id_type == "OBJECT":
        obj = bpy.data.objects.get(id_name)
        if obj is None:
            raise ProviderError("no object named %r" % id_name)
        return obj
    if id_type == "KEY":
        datablock = bpy.data.shape_keys.get(id_name)
        if datablock is None:
            raise ProviderError("no Key datablock named %r" % id_name)
        return datablock
    if id_type == "GREASE_PENCIL":
        for obj in bpy.data.objects:
            if obj.type == "GREASEPENCIL" and obj.data is not None \
                    and obj.data.name == id_name:
                return obj
        raise ProviderError("no Grease Pencil datablock named %r" % id_name)
    raise ProviderError(
        "channel id type %r is not resolvable by this provider build"
        % id_type)


def _anim_owners():
    owners = [(obj, "OBJECT") for obj in bpy.data.objects]
    owners.extend((datablock, "KEY") for datablock in bpy.data.shape_keys)
    return owners


def _capture_key(kp):
    interp = kp.interpolation
    bezier = interp == "BEZIER"
    return {
        "frame": fmt6(kp.co.x),
        "value": fmt6(kp.co.y),
        "interp": interp,
        "easing": kp.easing if interp in EASING_INTERPS else None,
        "handle_left": (
            [fmt6(kp.handle_left.x), fmt6(kp.handle_left.y)] if bezier else None
        ),
        "handle_right": (
            [fmt6(kp.handle_right.x), fmt6(kp.handle_right.y)] if bezier else None
        ),
        "handle_left_type": kp.handle_left_type if bezier else None,
        "handle_right_type": kp.handle_right_type if bezier else None,
        "back": fmt6(kp.back) if interp == "BACK" else None,
        "amplitude": fmt6(kp.amplitude) if interp == "ELASTIC" else None,
        "period": fmt6(kp.period) if interp == "ELASTIC" else None,
    }


def _capture_fcurve(id_type, id_name, slot_id, fc, label):
    if len(fc.modifiers) > 0:
        raise ProviderError(
            "F-curve modifiers on channel %s of %s: modifiers are "
            "evaluation-time state outside the key set "
            "(DESIGN-ANIM §3); capture refuses" % (fc.data_path, label))
    return {
        "id": {"type": id_type, "name": id_name},
        "slot": slot_id,
        "path": fc.data_path,
        "index": fc.array_index,
        "extrapolation": fc.extrapolation,
        "keys": [_capture_key(kp) for kp in fc.keyframe_points],
    }


def _apply_key(kp, key):
    kp.interpolation = key["interp"]
    if key.get("easing") is not None:
        kp.easing = key["easing"]
    if key["interp"] == "BEZIER":
        kp.handle_left_type = key["handle_left_type"]
        kp.handle_right_type = key["handle_right_type"]
        kp.handle_left = (float(key["handle_left"][0]),
                          float(key["handle_left"][1]))
        kp.handle_right = (float(key["handle_right"][0]),
                           float(key["handle_right"][1]))
    if key["interp"] == "BACK":
        kp.back = float(key["back"])
    if key["interp"] == "ELASTIC":
        kp.amplitude = float(key["amplitude"])
        kp.period = float(key["period"])


def _write_fcurve(fcurves, channel):
    path, index = channel["path"], channel["index"]
    for fc in list(fcurves):
        if fc.data_path == path and fc.array_index == index:
            fcurves.remove(fc)
            break
    fc = fcurves.new(path, index=index)
    fc.extrapolation = channel["extrapolation"]
    for key in channel["keys"]:
        kp = fc.keyframe_points.insert(float(key["frame"]),
                                       float(key["value"]))
        _apply_key(kp, key)
    fc.update()
    return fc


def _find_fcurve(fcurves, path, index):
    for fc in fcurves:
        if fc.data_path == path and fc.array_index == index:
            return fc
    return None


def _action_name(take_id, id_name):
    raw = "%s_%s" % (take_id, id_name)
    return re.sub(r"[^A-Za-z0-9_.\-]+", "_", raw)[:60]


# ---------------------------------------------------------------------------
# GP frame-range machinery: per-frame drawings through the v1
# artifact shape. v1's capture_gp merges every frame into one
# artifact; the range ops keep frames apart (DESIGN-ANIM §1.3).
# ---------------------------------------------------------------------------

def _drawing_strokes(drawing):
    strokes_out = []
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
    return strokes_out


def _capture_frame_artifact(object_name, layer_name, frame):
    artifact = {
        "schema": SCHEMA,
        "kind": "gp_strokes",
        "id": "capture-" + object_name,
        "created_by": PROVIDER_NAME + " " + PROVIDER_VERSION,
        "target": {"object": object_name, "layer": layer_name,
                   "frame": frame.frame_number},
        "strokes": _drawing_strokes(frame.drawing),
    }
    artifact["sha256"] = content_hash(artifact)
    validate_artifact(artifact)
    _ARTIFACT_STORE[artifact["sha256"]] = artifact
    return artifact


def _write_drawing(drawing, strokes):
    counts = [len(stroke["points"]) for stroke in strokes]
    drawing.add_strokes(counts)
    colour_values = []
    have_colour = False
    for s_index, stroke in enumerate(strokes):
        gp_stroke = drawing.strokes[s_index]
        colour = stroke.get("colour")
        for p_index, point in enumerate(stroke["points"]):
            gp_point = gp_stroke.points[p_index]
            gp_point.position = [dec(axis, "p") for axis in point["p"]]
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


def _replay_track(track, artifacts):
    resolved = []
    for entry in track["frames"]:
        digest = entry["artifact"]
        artifact = artifacts.get(digest) or _ARTIFACT_STORE.get(digest)
        if artifact is None:
            raise ProviderError(
                "GP track references artifact %s, which was not "
                "supplied and is not in this session's capture "
                "store (refused before mutation)" % digest)
        kind, _ = validate_artifact(artifact)
        if kind != "gp_strokes":
            raise ProviderError(
                "GP track reference %s is a %s artifact, not "
                "gp_strokes" % (digest, kind))
        _ARTIFACT_STORE[digest] = artifact
        resolved.append((entry["frame"], artifact))
    name = track["object"]
    existing = bpy.data.objects.get(name)
    if existing is not None:
        bpy.data.objects.remove(existing, do_unlink=True)
    data = bpy.data.grease_pencils.new(name)
    obj = bpy.data.objects.new(name, data)
    bpy.context.scene.collection.objects.link(obj)
    layer = data.layers.new(track["layer"], set_active=True)
    for frame_number, artifact in resolved:
        frame = layer.frames.new(frame_number)
        _write_drawing(frame.drawing, artifact["strokes"])
    return {"object": obj.name, "frames": len(resolved)}


# ---------------------------------------------------------------------------
# Ops 13-25 (DESIGN-ANIM §2)
# ---------------------------------------------------------------------------

def pose_capture(params):
    frame = params.get("frame")
    if not isinstance(frame, int) or isinstance(frame, bool) or frame < 0:
        raise ProviderError("pose_capture requires an integer \"frame\"",
                            INVALID_PARAMS)
    channels = []
    for datablock, fallback_type in _anim_owners():
        adt = datablock.animation_data
        if adt is None or adt.action is None:
            continue
        _check_anim_exclusions(adt, datablock.name)
        slot, fcurves = _fcurves_for_read(adt, datablock.name)
        id_type = slot.target_id_type if slot is not None else fallback_type
        slot_id = slot.identifier if slot is not None else None
        for fc in fcurves:
            if len(fc.keyframe_points) == 0:
                continue
            if len(fc.modifiers) > 0:
                raise ProviderError(
                    "F-curve modifiers on channel %s of %s "
                    "(DESIGN-ANIM §3); capture refuses"
                    % (fc.data_path, datablock.name))
            channels.append({
                "id": {"type": id_type, "name": datablock.name},
                "slot": slot_id,
                "path": fc.data_path,
                "index": fc.array_index,
                "value": fmt6(fc.evaluate(float(frame))),
                "handle_left": None,
                "handle_right": None,
                "handle_left_type": None,
                "handle_right_type": None,
            })
    if not channels:
        raise ProviderError(
            "the bound scene holds no animated channels to pose from")
    channels.sort(key=_channel_address)
    pose = {
        "schema": POSE_SCHEMA,
        "id": "pose-%d" % frame,
        "created_by": PROVIDER_NAME + " " + PROVIDER_VERSION,
        "target": {"scene_sha256": _scene_sha256()},
        "frame": frame,
        "channels": channels,
        "insert": {"interp": "LINEAR"},
    }
    pose["sha256"] = content_hash(pose)
    validate_pose(pose)
    return {"pose": pose}


def pose_apply(params):
    pose = params.get("pose")
    info = validate_pose(pose)
    _check_scene_binding(pose["target"]["scene_sha256"])
    interp = pose["insert"]["interp"]
    frame = float(pose["frame"])
    for channel in pose["channels"]:
        owner = _resolve_owner(channel["id"]["type"], channel["id"]["name"])
        fcurves = _fcurves_for_write(
            owner, channel["id"]["type"], channel["id"]["name"], None)
        fc = _find_fcurve(fcurves, channel["path"], channel["index"])
        if fc is None:
            fc = fcurves.new(channel["path"], index=channel["index"])
        key = {
            "interp": interp,
            "easing": None,
            "handle_left": channel.get("handle_left"),
            "handle_right": channel.get("handle_right"),
            "handle_left_type": channel.get("handle_left_type"),
            "handle_right_type": channel.get("handle_right_type"),
            "back": None, "amplitude": None, "period": None,
        }
        target_kp = None
        for kp in fc.keyframe_points:
            if kp.co.x == frame:
                target_kp = kp
                break
        if target_kp is None:
            target_kp = fc.keyframe_points.insert(
                frame, float(channel["value"]))
        else:
            target_kp.co.y = float(channel["value"])
        _apply_key(target_kp, key)
        fc.update()
    bpy.context.view_layer.update()
    return {"id": info["id"], "frame": pose["frame"],
            "channels": info["channels"]}


def curve_capture(params):
    id_type = params.get("id_type")
    id_name = params.get("id_name")
    path = params.get("path")
    index = params.get("index")
    if not isinstance(id_type, str) or not isinstance(id_name, str) \
            or not isinstance(path, str) \
            or not isinstance(index, int) or isinstance(index, bool):
        raise ProviderError(
            "curve_capture requires id_type, id_name, path, index",
            INVALID_PARAMS)
    owner = _resolve_owner(id_type, id_name)
    adt = owner.animation_data
    if adt is None or adt.action is None:
        raise ProviderError("%s %r holds no action" % (id_type, id_name))
    _check_anim_exclusions(adt, id_name)
    slot_wanted = params.get("slot")
    if isinstance(slot_wanted, str) and slot_wanted:
        slot = None
        for candidate in adt.action.slots:
            if candidate.identifier == slot_wanted:
                slot = candidate
                break
        if slot is None:
            raise ProviderError(
                "action on %r has no slot %r" % (id_name, slot_wanted))
        if len(adt.action.layers) == 0:
            fcurves = adt.action.fcurves
        else:
            strips = [
                strip
                for layer in adt.action.layers
                for strip in layer.strips
                if strip.type == "KEYFRAME"
            ]
            if len(strips) > 1:
                raise ProviderError(
                    "multi-strip layered action on %s; capture "
                    "refuses (DESIGN-ANIM §3)" % id_name)
            bag = strips[0].channelbag(slot) if strips else None
            fcurves = bag.fcurves if bag is not None else []
    else:
        slot, fcurves = _fcurves_for_read(adt, id_name)
    fc = _find_fcurve(fcurves, path, index)
    if fc is None:
        raise ProviderError(
            "no channel %s[%d] on %s %r" % (path, index, id_type, id_name))
    if len(fc.keyframe_points) == 0:
        raise ProviderError(
            "channel %s[%d] on %r holds no keys" % (path, index, id_name))
    channel = _capture_fcurve(
        id_type, id_name,
        slot.identifier if slot is not None else None, fc, id_name)
    return {"channel": channel}


def curve_apply(params):
    channel = params.get("channel")
    if not isinstance(channel, dict):
        raise ProviderError("curve_apply requires a \"channel\" object",
                            INVALID_PARAMS)
    _check_channel_head(channel, "channel", True)
    keys = channel.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ProviderError("channel.keys must be a non-empty array")
    if len(keys) > MAX_KEYS_PER_CHANNEL:
        raise ProviderError(
            "channel carries %d keys; the bound is %d (refused, not "
            "truncated)" % (len(keys), MAX_KEYS_PER_CHANNEL))
    previous = None
    for key_index, key in enumerate(keys):
        frame = _check_key(key, "channel.keys[%d]" % key_index)
        if previous is not None and frame <= previous:
            raise ProviderError("channel keys do not ascend by frame")
        previous = frame
    claimed = params.get("scene_sha256")
    if not _is_sha256(claimed):
        raise ProviderError(
            "curve_apply requires the open scene's \"scene_sha256\"",
            INVALID_PARAMS)
    _check_scene_binding(claimed)
    owner = _resolve_owner(channel["id"]["type"], channel["id"]["name"])
    fcurves = _fcurves_for_write(
        owner, channel["id"]["type"], channel["id"]["name"], None)
    _write_fcurve(fcurves, channel)
    bpy.context.view_layer.update()
    return {"channel": _channel_address(channel)}


def take_capture(params):
    scene = bpy.context.scene
    channels = []
    for datablock, fallback_type in _anim_owners():
        adt = datablock.animation_data
        if adt is None or adt.action is None:
            continue
        _check_anim_exclusions(adt, datablock.name)
        slot, fcurves = _fcurves_for_read(adt, datablock.name)
        id_type = slot.target_id_type if slot is not None else fallback_type
        slot_id = slot.identifier if slot is not None else None
        for fc in fcurves:
            if len(fc.keyframe_points) == 0:
                continue
            channels.append(_capture_fcurve(
                id_type, datablock.name, slot_id, fc, datablock.name))
    channels.sort(key=_channel_address)
    gp_tracks = []
    artifacts = {}
    gp_objects = sorted(
        (o for o in bpy.data.objects if o.type == "GREASEPENCIL"),
        key=lambda o: o.name)
    for obj in gp_objects:
        for layer in obj.data.layers:
            frames = []
            for frame in sorted(layer.frames, key=lambda f: f.frame_number):
                artifact = _capture_frame_artifact(obj.name, layer.name, frame)
                artifacts[artifact["sha256"]] = artifact
                frames.append({"frame": frame.frame_number,
                               "artifact": artifact["sha256"]})
            if frames:
                gp_tracks.append({"object": obj.name, "layer": layer.name,
                                  "frames": frames})
    if not channels and not gp_tracks:
        raise ProviderError(
            "the bound scene holds no authored animation to capture")
    all_frames = [float(k["frame"]) for c in channels for k in c["keys"]]
    all_frames += [float(e["frame"]) for t in gp_tracks for e in t["frames"]]
    rig = next((o.name for o in bpy.data.objects if o.type == "ARMATURE"),
               None)
    take = {
        "schema": TAKE_SCHEMA,
        "id": params.get("id") or ("capture-" + (rig or scene.name or "scene")),
        "created_by": PROVIDER_NAME + " " + PROVIDER_VERSION,
        "target": {"scene_sha256": _scene_sha256(), "rig": rig},
        "frames": {
            "start": int(math.floor(min(all_frames))),
            "end": int(math.ceil(max(all_frames))),
            **_fps_block(),
        },
        "channels": channels,
        "gp_tracks": gp_tracks,
        "bake": None,
    }
    take["sha256"] = content_hash(take)
    info = validate_take(take)
    return {"take": take, "artifacts": artifacts,
            "action_digest": action_digest(take), **info}


def take_apply(params):
    take = params.get("take")
    info = validate_take(take)
    _check_scene_binding(take["target"]["scene_sha256"])
    artifacts = params.get("artifacts")
    if isinstance(artifacts, dict):
        for digest, artifact in artifacts.items():
            if isinstance(artifact, dict):
                _ARTIFACT_STORE[digest] = artifact
    for track in take["gp_tracks"]:
        for entry in track["frames"]:
            if entry["artifact"] not in _ARTIFACT_STORE:
                raise ProviderError(
                    "take GP track references artifact %s, which was "
                    "not supplied and is not in this session's "
                    "capture store (refused before mutation)"
                    % entry["artifact"])
    groups = {}
    for channel in take["channels"]:
        key = (channel["id"]["type"], channel["id"]["name"])
        groups.setdefault(key, []).append(channel)
    for (id_type, id_name), group in groups.items():
        owner = _resolve_owner(id_type, id_name)
        fcurves = _fcurves_for_write(
            owner, id_type, id_name, _action_name(take["id"], id_name))
        for channel in group:
            _write_fcurve(fcurves, channel)
    for track in take["gp_tracks"]:
        _replay_track(track, {})
    bpy.context.view_layer.update()
    return {**info, "action_digest": action_digest(take)}


def take_validate(params):
    take = params.get("take")
    pose = params.get("pose")
    if isinstance(take, dict):
        info = validate_take(take)
        return {"valid": True, "kind": "take",
                "action_digest": action_digest(take), **info}
    if isinstance(pose, dict):
        info = validate_pose(pose)
        return {"valid": True, "kind": "pose", **info}
    raise ProviderError("take_validate requires a \"take\" or \"pose\" "
                        "object", INVALID_PARAMS)


def gp_capture_range(params):
    object_name = params.get("object")
    layer_name = params.get("layer")
    start = params.get("start")
    end = params.get("end")
    if not isinstance(object_name, str) or not isinstance(layer_name, str) \
            or not isinstance(start, int) or isinstance(start, bool) \
            or not isinstance(end, int) or isinstance(end, bool) \
            or end < start:
        raise ProviderError(
            "gp_capture_range requires object, layer, start, end",
            INVALID_PARAMS)
    if end - start > MAX_FRAME_SPAN:
        raise ProviderError(
            "range spans %d frames; the bound is %d (refused, not "
            "truncated)" % (end - start, MAX_FRAME_SPAN))
    obj = bpy.data.objects.get(object_name)
    if obj is None or obj.type != "GREASEPENCIL":
        raise ProviderError("no Grease Pencil object named %r" % object_name)
    layer = obj.data.layers.get(layer_name)
    if layer is None:
        raise ProviderError(
            "Grease Pencil object %r has no layer %r" % (object_name, layer_name))
    frames = []
    artifacts = {}
    for frame in sorted(layer.frames, key=lambda f: f.frame_number):
        if start <= frame.frame_number <= end:
            artifact = _capture_frame_artifact(object_name, layer_name, frame)
            artifacts[artifact["sha256"]] = artifact
            frames.append({"frame": frame.frame_number,
                           "artifact": artifact["sha256"]})
    if not frames:
        raise ProviderError(
            "layer %r of %r holds no frames within %d..=%d"
            % (layer_name, object_name, start, end))
    track = {"object": object_name, "layer": layer_name, "frames": frames}
    return {"track": track, "artifacts": artifacts}


def gp_replay_range(params):
    track = params.get("track")
    artifacts = params.get("artifacts")
    if not isinstance(track, dict) or not isinstance(track.get("frames"), list) \
            or not isinstance(track.get("object"), str) \
            or not isinstance(track.get("layer"), str):
        raise ProviderError(
            "gp_replay_range requires a \"track\" object (object, "
            "layer, frames)", INVALID_PARAMS)
    if not isinstance(artifacts, dict):
        artifacts = {}
    return _replay_track(track, artifacts)


def take_render(params):
    take = params.get("take")
    path = params.get("path")
    if not isinstance(path, str) or not path:
        raise ProviderError("take_render requires a \"path\" prefix",
                            INVALID_PARAMS)
    take_apply(params)
    scene = bpy.context.scene
    if scene.camera is None:
        raise ProviderError("the scene has no camera")
    render = scene.render
    frames_block = take["frames"]
    previous = (
        scene.frame_start, scene.frame_end, scene.frame_current,
        render.fps, render.fps_base, render.filepath,
        render.image_settings.file_format,
        render.resolution_x, render.resolution_y,
    )
    try:
        scene.frame_start = frames_block["start"]
        scene.frame_end = frames_block["end"]
        render.fps = frames_block["fps_num"]
        render.fps_base = float(frames_block["fps_base"])
        if isinstance(params.get("width"), int):
            render.resolution_x = params["width"]
        if isinstance(params.get("height"), int):
            render.resolution_y = params["height"]
        render.image_settings.file_format = "PNG"
        render.filepath = path
        bpy.ops.render.render(animation=True)
    finally:
        (scene.frame_start, scene.frame_end, scene.frame_current,
         render.fps, render.fps_base, render.filepath,
         render.image_settings.file_format,
         render.resolution_x, render.resolution_y) = previous
    frames_out = []
    for frame in range(frames_block["start"], frames_block["end"] + 1):
        candidate = "%s%04d.png" % (path, frame)
        if not os.path.isfile(candidate):
            raise ProviderError("render did not produce %s" % candidate)
        frames_out.append(candidate)
    return {"path": path, "frames": frames_out, "count": len(frames_out)}


def contact_sheet(params):
    frames = params.get("frames")
    path = params.get("path")
    if not isinstance(frames, list) or not frames \
            or not isinstance(path, str) or not path:
        raise ProviderError(
            "contact_sheet requires \"frames\" and \"path\"", INVALID_PARAMS)
    columns = params.get("columns")
    if not isinstance(columns, int) or isinstance(columns, bool) or columns < 1:
        columns = int(math.ceil(math.sqrt(len(frames))))
    rows = int(math.ceil(len(frames) / float(columns)))
    loaded = []
    try:
        for frame_path in frames:
            if not os.path.isfile(frame_path):
                raise ProviderError("no such frame file: %s" % frame_path)
            loaded.append(bpy.data.images.load(frame_path,
                                               check_existing=False))
        width, height = loaded[0].size
        for image in loaded:
            if tuple(image.size) != (width, height):
                raise ProviderError(
                    "contact sheet frames must share one size; %s is "
                    "%s, expected (%d, %d)"
                    % (image.name, tuple(image.size), width, height))
        sheet = bpy.data.images.new(
            "SeahawkContactSheet", width * columns, height * rows,
            alpha=True)
        pixels = [0.0] * (width * columns * height * rows * 4)
        for position, image in enumerate(loaded):
            col = position % columns
            row_from_top = position // columns
            y_base = (rows - 1 - row_from_top) * height
            x_base = col * width
            frame_pixels = [0.0] * (width * height * 4)
            image.pixels.foreach_get(frame_pixels)
            for y in range(height):
                src = y * width * 4
                dst = ((y_base + y) * width * columns + x_base) * 4
                pixels[dst:dst + width * 4] = frame_pixels[src:src + width * 4]
        sheet.pixels.foreach_set(pixels)
        sheet.update()
        previous_format = sheet.file_format
        previous_path = sheet.filepath_raw
        try:
            sheet.file_format = "PNG"
            sheet.filepath_raw = path
            sheet.save()
        finally:
            sheet.file_format = previous_format
            sheet.filepath_raw = previous_path
    finally:
        for image in loaded:
            bpy.data.images.remove(image)
    return {"path": path, "bytes": os.path.getsize(path),
            "frames": len(frames), "columns": columns, "rows": rows}


def sim_bake(params):
    system = params.get("system")
    objects = params.get("objects")
    start = params.get("start")
    end = params.get("end")
    if not isinstance(system, str) or not system \
            or not isinstance(objects, list) or not objects \
            or not all(isinstance(name, str) for name in objects) \
            or not isinstance(start, int) or isinstance(start, bool) \
            or not isinstance(end, int) or isinstance(end, bool) \
            or end < start:
        raise ProviderError(
            "sim_bake requires system, objects, start, end", INVALID_PARAMS)
    scene = bpy.context.scene
    frames_block = {"start": start, "end": end, **_fps_block()}
    _check_frames_block(frames_block, "sim_bake.frames")
    for name in objects:
        if bpy.data.objects.get(name) is None:
            raise ProviderError("no object named %r" % name)
    samples = {name: {"location": [], "rotation_quaternion": [], "scale": []}
               for name in objects}
    previous_frame = scene.frame_current
    try:
        for frame in range(start, end + 1):
            scene.frame_set(frame)
            bpy.context.view_layer.update()
            for name in objects:
                matrix = bpy.data.objects[name].matrix_world
                location = matrix.to_translation()
                quaternion = matrix.to_quaternion()
                scale = matrix.to_scale()
                samples[name]["location"].append(tuple(location))
                samples[name]["rotation_quaternion"].append(tuple(quaternion))
                samples[name]["scale"].append(tuple(scale))
    finally:
        scene.frame_set(previous_frame)
        bpy.context.view_layer.update()
    channels = []
    for name in objects:
        for path, components in (
            ("location", 3), ("rotation_quaternion", 4), ("scale", 3)
        ):
            for index in range(components):
                keys = []
                for offset, frame in enumerate(range(start, end + 1)):
                    keys.append({
                        "frame": fmt6(frame),
                        "value": fmt6(samples[name][path][offset][index]),
                        "interp": "LINEAR",
                        "easing": None,
                        "handle_left": None,
                        "handle_right": None,
                        "handle_left_type": None,
                        "handle_right_type": None,
                        "back": None,
                        "amplitude": None,
                        "period": None,
                    })
                channels.append({
                    "id": {"type": "OBJECT", "name": name},
                    "slot": None,
                    "path": path,
                    "index": index,
                    "extrapolation": "CONSTANT",
                    "keys": keys,
                })
    channels.sort(key=_channel_address)
    settings = {}
    bake = {
        "system": system,
        "blender": bpy.app.version_string,
        "frames": frames_block,
        "settings": settings,
        "settings_sha256": hashlib.sha256(
            canonical_bytes(settings)).hexdigest(),
        "channels": [_channel_address(c) for c in channels],
        "evidence": (
            "object-level evaluated bake (matrix_world per frame) "
            "by seahawk sim_bake; pose-bone constraint baking is "
            "not admitted in this build; admission is the caller's "
            "twin-bake comparison (DESIGN-ANIM S4.3); springs are "
            "provenance only."
        )
    }
    take = {
        "schema": TAKE_SCHEMA,
        "id": "bake-" + system,
        "created_by": PROVIDER_NAME + " " + PROVIDER_VERSION,
        "target": {"scene_sha256": _scene_sha256(), "rig": None},
        "frames": frames_block,
        "channels": channels,
        "gp_tracks": [],
        "bake": bake,
    }
    take["sha256"] = content_hash(take)
    info = validate_take(take)
    return {"take": take, "action_digest": action_digest(take), **info}


def take_export(params):
    export = params.get("export")
    path = params.get("path")
    if not isinstance(export, dict) or not isinstance(path, str) or not path:
        raise ProviderError("take_export requires \"export\" and \"path\"",
                            INVALID_PARAMS)
    if export.get("schema") != TAKE_EXPORT_SCHEMA:
        raise ProviderError(
            "take_export writes only %s documents" % TAKE_EXPORT_SCHEMA)
    claimed = export.get("sha256")
    if not _is_sha256(claimed) or content_hash(export) != claimed:
        raise ProviderError(
            "the export document's content hash does not verify; "
            "refused, not repaired")
    payload = canonical_bytes(export)
    with open(path, "wb") as handle:
        handle.write(payload)
    return {"path": path, "bytes": len(payload)}


# ---------------------------------------------------------------------------
# The ops (v1 twelve plus the DESIGN-ANIM thirteen)
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


    def pose_capture(self, params):
        return pose_capture(params)

    def pose_apply(self, params):
        return pose_apply(params)

    def curve_capture(self, params):
        return curve_capture(params)

    def curve_apply(self, params):
        return curve_apply(params)

    def take_capture(self, params):
        return take_capture(params)

    def take_apply(self, params):
        return take_apply(params)

    def take_validate(self, params):
        return take_validate(params)

    def gp_capture_range(self, params):
        return gp_capture_range(params)

    def gp_replay_range(self, params):
        return gp_replay_range(params)

    def take_render(self, params):
        return take_render(params)

    def contact_sheet(self, params):
        return contact_sheet(params)

    def sim_bake(self, params):
        return sim_bake(params)

    def take_export(self, params):
        return take_export(params)

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
        "pose_capture": pose_capture,
        "pose_apply": pose_apply,
        "curve_capture": curve_capture,
        "curve_apply": curve_apply,
        "take_capture": take_capture,
        "take_apply": take_apply,
        "take_validate": take_validate,
        "gp_capture_range": gp_capture_range,
        "gp_replay_range": gp_replay_range,
        "take_render": take_render,
        "contact_sheet": contact_sheet,
        "sim_bake": sim_bake,
        "take_export": take_export,
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
