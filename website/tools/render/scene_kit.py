# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Scene kit for the website illustrations, importable inside Blender.

Design grid: the same coordinates as the old SVGs (640 x 320 for the feature and
use-case pictures, 1200 x 600 for the hero), 1 grid px = 0.01 m in the scene.
Everything is placed in *screen space*: ``place(root, x, y, hc)`` puts the root so
that the point ``hc`` metres above its origin projects to grid point (x, y) through
the fixed orthographic camera. Builders return a root Empty; the whole kit shares
one material palette, one camera, one light rig and one backdrop.
"""
from __future__ import annotations

import math

import bpy
import bmesh
from mathutils import Matrix, Vector

PX = 0.01                 # metres per grid pixel
EL_DEG, AZ_DEG = 33.0, 32.0   # camera elevation and azimuth (degrees)
SOFT_W = 760.0                # overhead softbox power (W)
KEY_S = 1.35                  # key sun strength (W/m2); fill and rim follow
WORLD_STRENGTH = 0.2
FLOOR_C0, FLOOR_C1 = "#f8faff", "#eef2ff"
CARD_EMISSION = 0.05

HEX = {
    "blue900": "#1b3a9a", "blue600": "#2b57d6", "blue300": "#8aa9ff", "blue100": "#dbe4ff",
    "gold": "#f0a53a", "green": "#2bb673", "red": "#e0535a", "redlight": "#f6b4b7",
    "white": "#f6f8fc", "paper": "#f0f3f8", "light": "#e9eef7", "grey": "#cbd5e1", "mid": "#94a3b8",
    "slate": "#44546c", "dark": "#2a3648", "metal": "#c9d2df", "screen": "#eef3ff",
    "bg0": "#f8faff", "bg1": "#eef2ff",
}


def srgb_to_linear(c: float) -> float:
    c /= 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def rgba(hexstr: str):
    h = hexstr.lstrip("#")
    return tuple(srgb_to_linear(int(h[i:i + 2], 16)) for i in (0, 2, 4)) + (1.0,)


# ---------------------------------------------------------------- scene state
class _State:
    coll = None
    cam = None
    R = U = F = None       # camera basis in world space
    W = H = 0              # grid size
    texts: list = []
    boxes: dict = {}
    counter = 0

S = _State()


def _name(base: str) -> str:
    S.counter += 1
    return f"{base}.{S.counter:04d}"


# ---------------------------------------------------------------- materials
_MATS: dict = {}


def mat(key: str, rough: float = 0.5, metallic: float = 0.0, sheen: float = 0.3,
        emission: float = 0.0, spec: float = 0.35):
    """Matte, clay-like material from the shared palette (or a #hex)."""
    name = f"{key}|{rough}|{metallic}|{sheen}|{emission}|{spec}"
    if name in _MATS:
        return _MATS[name]
    m = bpy.data.materials.new(name)
    m.use_nodes = True
    bsdf = m.node_tree.nodes["Principled BSDF"]
    col = rgba(HEX.get(key, key))
    bsdf.inputs["Base Color"].default_value = col
    bsdf.inputs["Roughness"].default_value = rough
    bsdf.inputs["Metallic"].default_value = metallic
    bsdf.inputs["Specular IOR Level"].default_value = spec
    bsdf.inputs["Sheen Weight"].default_value = sheen
    bsdf.inputs["Sheen Roughness"].default_value = 0.4
    if emission:
        bsdf.inputs["Emission Color"].default_value = col
        bsdf.inputs["Emission Strength"].default_value = emission
    _MATS[name] = m
    return m


def gold():
    return mat("gold", rough=0.28, metallic=0.85, sheen=0.0, spec=0.6)


# ---------------------------------------------------------------- mesh helpers
def _link(ob, parent=None):
    S.coll.objects.link(ob)
    if parent is not None:
        ob.parent = parent
    return ob


def _finish(ob, m, bevel=0.0, segs=4, smooth=True, angle=40.0):
    me = ob.data
    if smooth:
        me.polygons.foreach_set("use_smooth", [True] * len(me.polygons))
    if m is not None:
        me.materials.append(m)
    if bevel:
        b = ob.modifiers.new("bevel", "BEVEL")
        b.width = bevel
        b.segments = segs
        b.limit_method = "ANGLE"
        b.angle_limit = math.radians(angle)
        b.harden_normals = True
    return ob


def empty(name="root", parent=None):
    ob = bpy.data.objects.new(_name(name), None)
    ob.empty_display_size = 0.1
    return _link(ob, parent)


def mesh_obj(name, verts, faces, m, bevel=0.0, segs=4, parent=None, smooth=True, angle=40.0):
    me = bpy.data.meshes.new(_name(name))
    me.from_pydata([Vector(v) for v in verts], [], faces)
    me.update()
    ob = bpy.data.objects.new(me.name, me)
    _link(ob, parent)
    return _finish(ob, m, bevel, segs, smooth, angle)


def box(w, d, h, m, bevel=0.012, segs=4, at=(0, 0, 0), parent=None, name="box"):
    """Axis-aligned box, origin at the bottom centre."""
    x, y, z = at
    hw, hd = w / 2, d / 2
    v = [(x - hw, y - hd, z), (x + hw, y - hd, z), (x + hw, y + hd, z), (x - hw, y + hd, z),
         (x - hw, y - hd, z + h), (x + hw, y - hd, z + h), (x + hw, y + hd, z + h), (x - hw, y + hd, z + h)]
    f = [(3, 2, 1, 0), (4, 5, 6, 7), (0, 1, 5, 4), (1, 2, 6, 5), (2, 3, 7, 6), (3, 0, 4, 7)]
    return mesh_obj(name, v, f, m, min(bevel, w / 2.2, d / 2.2, h / 2.2), segs, parent)


def rrect(w, h, r, n=8, cx=0.0, cy=0.0):
    """Rounded-rectangle polygon (counter-clockwise), centred on (cx, cy)."""
    r = min(r, w / 2, h / 2)
    pts = []
    corners = [(w / 2 - r, h / 2 - r), (-w / 2 + r, h / 2 - r), (-w / 2 + r, -h / 2 + r), (w / 2 - r, -h / 2 + r)]
    for i, (x, y) in enumerate(corners):
        a0 = math.pi / 2 * i
        for k in range(n + 1):
            a = a0 + (math.pi / 2) * k / n
            pts.append((cx + x + r * math.cos(a), cy + y + r * math.sin(a)))
    return pts


def prism(poly, t, m, bevel=0.0, segs=4, parent=None, name="prism", z0=0.0):
    """Extrude a 2D polygon (in XY) by t along +Z."""
    n = len(poly)
    verts = [(x, y, z0) for x, y in poly] + [(x, y, z0 + t) for x, y in poly]
    faces = [tuple(reversed(range(n))), tuple(range(n, 2 * n))]
    faces += [(i, (i + 1) % n, (i + 1) % n + n, i + n) for i in range(n)]
    return mesh_obj(name, verts, faces, m, bevel, segs, parent)


def plate(w, h, t, r, m, bevel=0.0, parent=None, name="plate", cx=0.0, cy=0.0, z0=0.0):
    """Rounded plate lying in XY (w along X, h along Y), thickness t along +Z."""
    return prism(rrect(w, h, r, 8, cx, cy), t, m, bevel or min(t / 2.5, 0.01), 3, parent, name, z0)


def _bm_obj(bm, name, m, bevel, segs, parent, angle=40.0):
    me = bpy.data.meshes.new(_name(name))
    bm.to_mesh(me)
    bm.free()
    ob = bpy.data.objects.new(me.name, me)
    _link(ob, parent)
    return _finish(ob, m, bevel, segs, True, angle)


def cyl(r, h, m, segs=48, bevel=0.0, r2=None, at=(0, 0, 0), parent=None, name="cyl", axis="Z"):
    bm = bmesh.new()
    bmesh.ops.create_cone(bm, cap_ends=True, cap_tris=False, segments=segs, radius1=r,
                          radius2=r if r2 is None else r2, depth=h)
    bmesh.ops.translate(bm, verts=bm.verts, vec=(0, 0, h / 2))
    if axis == "X":
        bmesh.ops.rotate(bm, verts=bm.verts, cent=(0, 0, 0), matrix=Matrix.Rotation(math.radians(90), 3, "Y"))
    elif axis == "Y":
        bmesh.ops.rotate(bm, verts=bm.verts, cent=(0, 0, 0), matrix=Matrix.Rotation(math.radians(-90), 3, "X"))
    bmesh.ops.translate(bm, verts=bm.verts, vec=at)
    return _bm_obj(bm, name, m, bevel, 3, parent)


def sphere(r, m, at=(0, 0, 0), parent=None, name="sphere", scale=(1, 1, 1)):
    bm = bmesh.new()
    bmesh.ops.create_uvsphere(bm, u_segments=48, v_segments=24, radius=r)
    bmesh.ops.scale(bm, verts=bm.verts, vec=scale)
    bmesh.ops.translate(bm, verts=bm.verts, vec=at)
    return _bm_obj(bm, name, m, 0, 0, parent)


def torus(R, r, m, at=(0, 0, 0), parent=None, name="torus", segs=48, rings=20):
    verts, faces = [], []
    for i in range(segs):
        a = 2 * math.pi * i / segs
        for j in range(rings):
            b = 2 * math.pi * j / rings
            verts.append((at[0] + (R + r * math.cos(b)) * math.cos(a), at[1] + (R + r * math.cos(b)) * math.sin(a), at[2] + r * math.sin(b)))
    for i in range(segs):
        for j in range(rings):
            a, b = i * rings + j, ((i + 1) % segs) * rings + j
            faces.append((a, b, ((i + 1) % segs) * rings + (j + 1) % rings, i * rings + (j + 1) % rings))
    return mesh_obj(name, verts, faces, m, 0, 0, parent)


def tube(p0, p1, r, m, parent=None, segs=24, caps=True):
    """Straight cylinder between two points."""
    p0, p1 = Vector(p0), Vector(p1)
    d = p1 - p0
    L = d.length
    bm = bmesh.new()
    bmesh.ops.create_cone(bm, cap_ends=caps, cap_tris=False, segments=segs, radius1=r, radius2=r, depth=L)
    bmesh.ops.translate(bm, verts=bm.verts, vec=(0, 0, L / 2))
    rot = d.normalized().to_track_quat("Z", "Y").to_matrix()
    bmesh.ops.transform(bm, verts=bm.verts, matrix=Matrix.Translation(p0) @ rot.to_4x4())
    return _bm_obj(bm, "tube", m, 0, 0, parent)


def capsule(p0, p1, r, m, parent=None):
    """Tube with rounded ends."""
    ob = tube(p0, p1, r, m, parent, caps=True)
    sphere(r, m, at=p0, parent=parent)
    sphere(r, m, at=p1, parent=parent)
    return ob


def cone(r, h, m, at=(0, 0, 0), parent=None, direction=(0, 0, 1)):
    bm = bmesh.new()
    bmesh.ops.create_cone(bm, cap_ends=True, cap_tris=False, segments=32, radius1=r, radius2=0.0, depth=h)
    bmesh.ops.translate(bm, verts=bm.verts, vec=(0, 0, h / 2))
    rot = Vector(direction).normalized().to_track_quat("Z", "Y").to_matrix()
    bmesh.ops.transform(bm, verts=bm.verts, matrix=Matrix.Translation(Vector(at)) @ rot.to_4x4())
    return _bm_obj(bm, "cone", m, 0, 0, parent)


def metaball(elements, m, parent=None, name="meta", res=0.02):
    """Smooth union of balls: elements = [(x, y, z, radius), ...]; a negative radius subtracts."""
    mb = bpy.data.metaballs.new(_name(name))
    mb.resolution = res
    mb.render_resolution = res
    mb.threshold = 0.6
    for x, y, z, r in elements:
        el = mb.elements.new()
        el.co = (x, y, z)
        el.radius = abs(r)
        el.stiffness = 2.0
        el.use_negative = r < 0
    mb.materials.append(m)
    ob = bpy.data.objects.new(mb.name, mb)
    return _link(ob, parent)


# ---------------------------------------------------------------- scene setup
def new_scene(width_px: int, height_px: int, scale: int = 2, samples: int = 160, gpu: str = "OPTIX"):
    """Fresh scene with camera, lights and backdrop for a width_px x height_px grid."""
    bpy.ops.wm.read_factory_settings(use_empty=True)
    _MATS.clear()
    S.texts, S.boxes, S.counter = [], {}, 0
    S.W, S.H = width_px, height_px
    scene = bpy.context.scene
    S.coll = bpy.data.collections.new("kit")
    scene.collection.children.link(S.coll)

    # Camera: orthographic, fixed studio angle, looking at the grid centre.
    cam_data = bpy.data.cameras.new("cam")
    cam_data.type = "ORTHO"
    cam_data.ortho_scale = width_px * PX
    cam_data.clip_end = 200
    cam = bpy.data.objects.new("cam", cam_data)
    cam.rotation_euler = (math.radians(90 - EL_DEG), 0.0, math.radians(AZ_DEG))
    S.coll.objects.link(cam)
    scene.camera = cam
    bpy.context.view_layer.update()
    M = cam.matrix_world.to_3x3()
    S.R, S.U, S.F = M @ Vector((1, 0, 0)), M @ Vector((0, 1, 0)), -(M @ Vector((0, 0, 1)))
    # The camera sits on the view ray through the world origin, so a world point
    # projects to grid (W/2 + P.R / PX, H/2 - P.U / PX) exactly (see project()).
    cam.location = -S.F * 40
    S.cam = cam

    # Backdrop: a large matte floor with the page's gradient (#f8faff top-left to
    # #eef2ff bottom-right in screen space), shaded by the rig so soft shadows and
    # a gentle falloff are part of the picture.
    floor = mesh_obj("floor", [(-60, -60, 0), (60, -60, 0), (60, 60, 0), (-60, 60, 0)], [(0, 1, 2, 3)],
                     None, smooth=False)
    fm = bpy.data.materials.new("floor")
    fm.use_nodes = True
    nt = fm.node_tree
    bsdf = nt.nodes["Principled BSDF"]
    bsdf.inputs["Roughness"].default_value = 1.0
    bsdf.inputs["Specular IOR Level"].default_value = 0.0
    bsdf.inputs["Sheen Weight"].default_value = 0.0
    coord = nt.nodes.new("ShaderNodeTexCoord")
    dot = nt.nodes.new("ShaderNodeVectorMath")
    dot.operation = "DOT_PRODUCT"
    diag = Vector((S.R.x - S.U.x, S.R.y - S.U.y, 0.0)).normalized()
    dot.inputs[1].default_value = diag
    rng = nt.nodes.new("ShaderNodeMapRange")
    half = width_px * PX * 0.75
    rng.inputs["From Min"].default_value = -half
    rng.inputs["From Max"].default_value = half
    ramp = nt.nodes.new("ShaderNodeValToRGB")
    ramp.color_ramp.elements[0].color = rgba(FLOOR_C0)
    ramp.color_ramp.elements[1].color = rgba(FLOOR_C1)
    nt.links.new(coord.outputs["Object"], dot.inputs[0])
    nt.links.new(dot.outputs["Value"], rng.inputs["Value"])
    nt.links.new(rng.outputs["Result"], ramp.inputs["Fac"])
    nt.links.new(ramp.outputs["Color"], bsdf.inputs["Base Color"])
    floor.data.materials.append(fm)

    # Light rig relative to the camera. Suns give the same irradiance everywhere on
    # the floor (every object in every scene gets the same shadow), their angular
    # size keeps the shadows soft; an overhead softbox adds the studio ambience.
    Fh = Vector((S.F.x, S.F.y, 0)).normalized()
    _area("soft", Vector((0, 0, 9.0)) - Fh * 1.0, SOFT_W, 14.0, "#ffffff")
    _sun("key", (-S.R * 1.0 - Fh * 0.7 + Vector((0, 0, 1.25))), KEY_S, 10.0, "#fff8f0")
    _sun("fill", (S.R * 1.0 - Fh * 0.4 + Vector((0, 0, 0.7))), KEY_S * 0.3, 30.0, "#f2f5ff")
    _sun("rim", (Fh * 1.0 - S.R * 0.3 + Vector((0, 0, 0.8))), KEY_S * 0.35, 20.0, "#dbe4ff")
    world = bpy.data.worlds.new("world")
    scene.world = world
    world.use_nodes = True
    bg = world.node_tree.nodes["Background"]
    bg.inputs["Color"].default_value = rgba("#eef2ff")
    bg.inputs["Strength"].default_value = WORLD_STRENGTH

    # Render settings.
    scene.render.engine = "CYCLES"
    scene.render.resolution_x = width_px * scale
    scene.render.resolution_y = height_px * scale
    scene.render.resolution_percentage = 100
    scene.render.film_transparent = False
    scene.render.filter_size = 1.5
    scene.render.image_settings.file_format = "PNG"
    scene.render.image_settings.color_mode = "RGB"
    scene.render.image_settings.compression = 60
    scene.cycles.samples = samples
    scene.cycles.use_denoising = True
    scene.cycles.denoiser = "OPENIMAGEDENOISE"
    scene.cycles.denoising_use_gpu = False
    scene.cycles.tile_size = 512
    scene.render.use_persistent_data = False
    scene.cycles.max_bounces = 6
    scene.cycles.caustics_reflective = False
    scene.cycles.caustics_refractive = False
    scene.cycles.use_adaptive_sampling = True
    scene.cycles.adaptive_threshold = 0.01
    scene.view_settings.view_transform = "Standard"
    scene.view_settings.look = "None"
    scene.view_settings.exposure = 0.0
    scene.view_settings.gamma = 1.0
    _setup_device(scene, gpu)
    return scene


def _sun(name, direction, strength, angle_deg, color):
    ld = bpy.data.lights.new(name, "SUN")
    ld.energy = strength
    ld.angle = math.radians(angle_deg)
    ld.color = rgba(color)[:3]
    ob = bpy.data.objects.new(name, ld)
    d = Vector(direction).normalized()
    ob.location = d * 10
    ob.rotation_euler = (-d).to_track_quat("-Z", "Y").to_euler()
    S.coll.objects.link(ob)
    return ob


def _area(name, pos, energy, size, color):
    ld = bpy.data.lights.new(name, "AREA")
    ld.energy = energy
    ld.size = size
    ld.color = rgba(color)[:3]
    ob = bpy.data.objects.new(name, ld)
    ob.location = pos
    target = Vector((0, 0, 0.3))
    ob.rotation_euler = (target - Vector(pos)).to_track_quat("-Z", "Y").to_euler()
    S.coll.objects.link(ob)
    return ob


def _setup_device(scene, gpu):
    prefs = bpy.context.preferences.addons["cycles"].preferences
    used = "CPU"
    if gpu in ("OPTIX", "CUDA"):
        try:
            prefs.compute_device_type = gpu
            prefs.get_devices()
            found = False
            for d in prefs.devices:
                d.use = (d.type == gpu)
                found = found or d.use
            if found:
                scene.cycles.device = "GPU"
                used = gpu
        except Exception as e:  # pragma: no cover
            print("GPU setup failed:", e)
    if used == "CPU":
        scene.cycles.device = "CPU"
    S.device = used
    return used


# ---------------------------------------------------------------- screen space
def grid_to_uv(x, y):
    return (x - S.W / 2) * PX, (S.H / 2 - y) * PX


def project(p) -> tuple:
    """World point -> grid pixel coordinates."""
    p = Vector(p)
    u, v = p.dot(S.R), p.dot(S.U)
    return u / PX + S.W / 2, S.H / 2 - v / PX


def ground_point(x, y, hc=0.0) -> Vector:
    """World point on the floor whose column at height hc projects to grid (x, y)."""
    u, v = grid_to_uv(x, y)
    R, U = S.R, S.U
    v -= hc * U.z
    det = R.x * U.y - R.y * U.x
    gx = (u * U.y - v * R.y) / det
    gy = (R.x * v - U.x * u) / det
    return Vector((gx, gy, 0.0))


def place(root, x, y, hc=0.0, rot_z=0.0, lift=0.0):
    """Place a root so its point hc above the origin shows at grid (x, y)."""
    p = ground_point(x, y, hc + lift)
    root.location = (p.x, p.y, lift)
    root.rotation_euler = (0, 0, math.radians(rot_z))
    return root


def billboard(root, x, y, depth_h=0.4, lift=0.0, toward=0.12):
    """Orient a root so its local XY plane faces the camera (local +Z towards the viewer)
    and its origin shows at grid (x, y). depth_h: height of the origin above the floor;
    toward: extra shift towards the camera (keeps icons in front of cards and screens)."""
    p = ground_point(x, y, depth_h + lift) + Vector((0, 0, depth_h + lift)) - S.F * toward
    sc = Vector(root.scale)
    M = Matrix((S.R, S.U, -S.F)).transposed().to_4x4()
    M.translation = p
    root.matrix_world = M @ Matrix.Diagonal((sc.x, sc.y, sc.z, 1.0))
    root["bb_x"], root["bb_y"] = float(x), float(y)
    return root


def on_card(card_root, child, x, y, toward=0.05):
    """Attach a billboard-style UI object to a card so it sits on the card's face at
    grid point (x, y), slightly towards the camera (no depth sorting surprises)."""
    cx, cy = card_root["bb_x"], card_root["bb_y"]
    sc = Vector(child.scale)
    child.parent = card_root
    child.matrix_parent_inverse = Matrix.Identity(4)
    child.location = ((x - cx) * PX, (cy - y) * PX, toward)
    child.rotation_euler = (0, 0, 0)
    child.scale = sc
    child["bb_x"], child["bb_y"] = float(x), float(y)
    return child


def card_point(card_root, x, y, toward=0.0):
    """World point on a card's face at grid (x, y), shifted towards the camera."""
    cx, cy = card_root["bb_x"], card_root["bb_y"]
    return card_root.matrix_world @ Vector(((x - cx) * PX, (cy - y) * PX, toward))


def facing_cam_rot_z():
    """Rotation about Z that turns an object's -Y front towards the camera's horizontal direction."""
    return AZ_DEG


# ---------------------------------------------------------------- bounding boxes
def _iter_meshes(root):
    for ob in root.children_recursive:
        if ob.type in ("MESH", "META"):
            yield ob


def screen_bbox(root):
    """Projected bounding box of a root hierarchy in grid pixels (x0, y0, x1, y1)."""
    bpy.context.view_layer.update()
    xs, ys = [], []
    for ob in _iter_meshes(root):
        mw = ob.matrix_world
        if ob.type == "META":
            for el in ob.data.elements:
                if el.use_negative:
                    continue
                for dx in (-1, 1):
                    for dy in (-1, 1):
                        for dz in (-1, 1):
                            r = el.radius * 0.8
                            x, y = project(mw @ (Vector(el.co) + Vector((dx * r, dy * r, dz * r))))
                            xs.append(x); ys.append(y)
            continue
        for c in ob.bound_box:
            x, y = project(mw @ Vector(c))
            xs.append(x); ys.append(y)
    if not xs:
        x, y = project(root.matrix_world.translation)
        return (x, y, x, y)
    return (min(xs), min(ys), max(xs), max(ys))


def register_box(name, root):
    S.boxes[name] = screen_bbox(root)
    return S.boxes[name]


# ---------------------------------------------------------------- text (composed later with Pillow)
def text(x, y, s, style="sub", anchor="m", color=None, free=False):
    """Queue a text item for compose.py (free=True: may sit on an object by design)."""
    S.texts.append({"type": "text", "x": x, "y": y, "text": s, "style": style, "anchor": anchor, "color": color, "free": free})


def pill2d(x, y, w, h, s, fill="#2bb673", color="#ffffff", style="small", alpha=255):
    S.texts.append({"type": "pill", "x": x, "y": y, "w": w, "h": h, "text": s, "fill": fill, "color": color,
                    "style": style, "alpha": alpha})


def rule2d(x0, y0, x1, y1, color="#e8edf7", width=1.5):
    S.texts.append({"type": "rule", "x0": x0, "y0": y0, "x1": x1, "y1": y1, "color": color, "width": width})


def caption(s):
    assert len(s) <= 64, f"caption too long ({len(s)}): {s}"
    text(S.W / 2, S.H - 26, s, "caption")


def layout():
    return {"w": S.W, "h": S.H, "texts": S.texts, "boxes": S.boxes}


# ================================================================ asset builders
# Every builder returns a root Empty at the floor-contact centre of the object,
# the object facing -Y (the camera side), axis-aligned with the world.

def cipher_blocks(parent, cols, rows, s=0.09, g=0.05, hi=None, z=0.0, x0=None, y0=None, h=0.014, plane="xy"):
    """Grid of small rounded blocks in two blue tones (the ciphertext motif).
    plane 'xy': lying on a surface at height z (facing +Z); 'xz': standing wall, facing -Y."""
    tones = ["blue300", "blue100", "blue300", "blue600x", "blue100", "blue300"]
    mats = {"blue300": mat("blue300"), "blue100": mat("#b8c9ff"), "blue600x": mat("#6f90f0"), "hi": mat("blue600")}
    W = cols * s + (cols - 1) * g
    Hh = rows * s + (rows - 1) * g
    x0 = -W / 2 if x0 is None else x0
    y0 = -Hh / 2 if y0 is None else y0
    i = 0
    for r in range(rows):
        for c in range(cols):
            m = mats["hi"] if hi is not None and (c, r) == hi else mats[tones[i % len(tones)]]
            i += 1
            px, py = x0 + c * (s + g) + s / 2, y0 + (rows - 1 - r) * (s + g) + s / 2
            if plane == "xy":
                box(s, s, h, m, bevel=0.02, at=(px, py, z), parent=parent, name="blk")
            else:
                b = box(s, h, s, m, bevel=0.02, at=(px, z, 0), parent=parent, name="blk")
                b.location = (0, 0, py)


def _screen_rows(parent, rows, w, x, y_top, pitch, h=0.07, z=0.004):
    """Placeholder/downloaded bars on a standing screen (local XY of a plate)."""
    for i, tone in enumerate(rows):
        m = mat("blue300") if tone else mat("#c9d6ff")
        plate(w, h, 0.012, 0.015, m, parent=parent, cx=x, cy=y_top - i * pitch, z0=z)


def laptop(screen="cipher", hi=(2, 1), scale=1.0):
    """Open laptop. screen: 'cipher' (blocks), 'lines', 'alert', 'photos', 'lock', None."""
    root = empty("laptop")
    base_m, key_m = mat("metal", rough=0.45), mat("slate")
    box(1.24, 0.84, 0.05, base_m, bevel=0.018, parent=root, name="base")
    plate(1.0, 0.36, 0.008, 0.02, key_m, parent=root, cx=0, cy=0.03, z0=0.05)
    plate(0.3, 0.2, 0.006, 0.02, mat("#b4bfd0"), parent=root, cx=0, cy=-0.26, z0=0.05)
    lid = empty("lid", root)
    lid.location = (0, 0.405, 0.03)
    lid.rotation_euler = (math.radians(78), 0, 0)
    plate(1.24, 0.80, 0.03, 0.025, mat("slate"), parent=lid, cy=0.40)
    scr = plate(1.14, 0.70, 0.006, 0.02, mat("screen", rough=0.35, emission=0.25, sheen=0), parent=lid, cy=0.41, z0=0.03)
    _screen_content(lid, screen, hi, 0.036, 0.41, 1.14, 0.70)
    root.scale = (scale,) * 3
    return root


def _screen_content(parent, kind, hi, z, cy, w, h):
    if kind == "cipher":
        g = empty("grid", parent)
        g.location = (0, cy, z)
        cipher_blocks(g, 5, 3, hi=hi)
    elif kind == "lines":
        for i, L in enumerate([0.5, 0.34, 0.5, 0.24]):
            plate(L, 0.04, 0.012, 0.02, mat("mid"), parent=parent, cx=-w / 2 + 0.14 + L / 2, cy=cy + 0.2 - i * 0.12, z0=z)
    elif kind == "alert":
        plate(0.8, 0.14, 0.01, 0.03, mat("#f7d9db"), parent=parent, cx=0, cy=cy + 0.18, z0=z)
        cyl(0.035, 0.014, mat("red"), parent=parent, at=(-0.3, cy + 0.18, z + 0.01))
        plate(0.36, 0.035, 0.012, 0.015, mat("#eca3a7"), parent=parent, cx=0.0, cy=cy + 0.18, z0=z + 0.01)
        g = empty("grid", parent)
        g.location = (0, cy - 0.1, z)
        cipher_blocks(g, 5, 1, s=0.08)
    elif kind == "photos":
        photo_grid(parent, 4, 2, 0.17, 0.04, z=z, cy=cy)
    elif kind == "lock":
        lk = padlock(scale=1.5)
        lk.parent = parent
        lk.location = (0, cy - 0.3, z + 0.08)
        lk.rotation_euler = (math.radians(-90), 0, 0)


def photo_grid(parent, cols, rows, s, g, z=0.004, cx=0.0, cy=0.0):
    tones = ["#9fb6ff", "#6f90f0", "#c0cfff", "#8aa9ff", "#a9bcff", "#5f80e8", "#cbd7ff"]
    W = cols * s + (cols - 1) * g
    Hh = rows * s + (rows - 1) * g
    i = 0
    for r in range(rows):
        for c in range(cols):
            plate(s, s, 0.01, 0.012, mat(tones[i % len(tones)]), parent=parent,
                  cx=cx - W / 2 + c * (s + g) + s / 2, cy=cy + Hh / 2 - r * (s + g) - s / 2, z0=z)
            i += 1


def monitor(screen="cipher", hi=(2, 1)):
    root = empty("monitor")
    plate(0.56, 0.3, 0.03, 0.06, mat("metal", rough=0.45), parent=root, cy=0.1)
    box(0.16, 0.09, 0.12, mat("#aab6c8"), bevel=0.01, at=(0, 0.1, 0.03), parent=root)
    panel = empty("panel", root)
    panel.location = (0, 0.1, 0.14)
    panel.rotation_euler = (math.radians(84), 0, 0)
    plate(1.0, 0.66, 0.04, 0.03, mat("slate"), parent=panel, cy=0.33)
    plate(0.9, 0.56, 0.006, 0.015, mat("screen", rough=0.35, emission=0.25, sheen=0), parent=panel, cy=0.34, z0=0.04)
    _screen_content(panel, screen, hi, 0.046, 0.34, 0.9, 0.56)
    return root


def phone(screen="cipher", scale=1.0, lean=8.0):
    """Standing phone, screen towards -Y. screen: 'cipher', 'rows', 'rows_red', 'photos', 'tree', None."""
    root = empty("phone")
    body = empty("body", root)
    body.rotation_euler = (math.radians(90 - lean), 0, 0)
    body.location = (0, 0, 0.004)
    plate(0.44, 0.84, 0.05, 0.09, mat("dark"), parent=body, cy=0.42, z0=-0.05)
    plate(0.38, 0.76, 0.006, 0.06, mat("screen", rough=0.35, emission=0.25, sheen=0), parent=body, cy=0.42)
    plate(0.12, 0.028, 0.008, 0.014, mat("dark"), parent=body, cy=0.80, z0=0.004)
    if screen == "cipher":
        g = empty("grid", body)
        g.location = (0, 0.46, 0.008)
        cipher_blocks(g, 3, 4, s=0.08, g=0.04)
    elif screen in ("rows", "rows_red"):
        rows = [0, 1, 0, 1] if screen == "rows" else [0, "red", 0, 0]
        for i, tone in enumerate(rows):
            m = mat("red") if tone == "red" else (mat("blue300") if tone else mat("#c9d6ff"))
            plate(0.3, 0.075, 0.01, 0.015, m, parent=body, cx=0, cy=0.64 - i * 0.12, z0=0.006)
    elif screen == "photos":
        photo_grid(body, 3, 5, 0.1, 0.02, z=0.006, cy=0.47)
        plate(0.3, 0.03, 0.01, 0.015, mat("#e2e8f0"), parent=body, cx=0, cy=0.12, z0=0.006)
        plate(0.28, 0.03, 0.012, 0.015, mat("red"), parent=body, cx=-0.01, cy=0.12, z0=0.007)
    elif screen == "tree":
        for i, (ind, w, tone) in enumerate([(0, 0.3, 0), (0.06, 0.24, 0), (0.06, 0.24, 1), (0, 0.3, 1), (0, 0.3, 0)]):
            m = mat("blue300") if tone else mat("#c9d6ff")
            plate(w, 0.07, 0.01, 0.015, m, parent=body, cx=ind / 2, cy=0.68 - i * 0.11, z0=0.006)
    elif screen == "thumbs":
        photo_grid(body, 2, 3, 0.12, 0.04, z=0.006, cy=0.47)
    root.scale = (scale,) * 3
    return root


def tablet(scale=1.0):
    root = empty("tablet")
    body = empty("body", root)
    body.rotation_euler = (math.radians(82), 0, 0)
    body.location = (0, 0, 0.004)
    plate(0.66, 0.86, 0.05, 0.08, mat("dark"), parent=body, cy=0.43, z0=-0.05)
    plate(0.58, 0.74, 0.006, 0.05, mat("screen", rough=0.35, emission=0.25, sheen=0), parent=body, cy=0.43)
    plate(0.44, 0.26, 0.01, 0.03, mat("blue300"), parent=body, cy=0.60, z0=0.006)
    for i, L in enumerate([0.44, 0.32, 0.40]):
        plate(L, 0.035, 0.01, 0.015, mat("mid"), parent=body, cx=-0.22 + L / 2, cy=0.36 - i * 0.09, z0=0.006)
    root.scale = (scale,) * 3
    return root


def nas(ok=True):
    root = empty("nas")
    box(0.8, 0.62, 0.52, mat("paper"), bevel=0.03, parent=root)
    for z in (0.33, 0.10):
        box(0.6, 0.03, 0.13, mat("light"), bevel=0.012, at=(0, -0.31, z), parent=root, name="bay")
        box(0.2, 0.012, 0.025, mat("grey"), bevel=0.006, at=(-0.14, -0.342, z + 0.05), parent=root, name="handle")
        led = cyl(0.025, 0.012, mat("green", emission=1.5, rough=0.3), parent=root, at=(0.22, -0.335, z + 0.065), axis="Y")
    return root


def disk(led="green", label=None):
    """3.5-inch hard disk lying flat, with the platter window on top."""
    root = empty("disk")
    box(0.8, 0.52, 0.12, mat("paper"), bevel=0.02, parent=root)
    cyl(0.17, 0.006, mat("grey"), parent=root, at=(-0.2, 0.02, 0.12))
    cyl(0.15, 0.01, mat("light"), parent=root, at=(-0.2, 0.02, 0.12))
    cyl(0.06, 0.016, mat("paper"), parent=root, at=(-0.2, 0.02, 0.12))
    cyl(0.018, 0.022, mat("mid"), parent=root, at=(-0.2, 0.02, 0.12))
    box(0.2, 0.03, 0.008, mat("grey"), bevel=0.004, at=(0.1, 0.09, 0.12), parent=root)
    box(0.13, 0.03, 0.008, mat("grey"), bevel=0.004, at=(0.065, 0.0, 0.12), parent=root)
    if led:
        cyl(0.03, 0.012, mat(led, emission=1.5, rough=0.3), parent=root, at=(0.3, -0.14, 0.12))
    return root


def shelf(letters=("A", "A", "B")):
    """Open shelf unit with one disk per compartment (letters are drawn by compose.py)."""
    root = empty("shelf")
    w, d, t = 1.1, 0.64, 0.035
    levels = [0.0, 0.36, 0.72, 1.08]
    m = mat("paper")
    for z in levels:
        box(w, d, t, m, bevel=0.012, at=(0, 0, z), parent=root, name="board")
    box(t, d, levels[-1] + t, m, bevel=0.012, at=(-w / 2 + t / 2, 0, 0), parent=root, name="side")
    box(t, d, levels[-1] + t, m, bevel=0.012, at=(w / 2 - t / 2, 0, 0), parent=root, name="side")
    box(w, t, levels[-1] + t, mat("light"), bevel=0.012, at=(0, d / 2 - t / 2, 0), parent=root, name="back")
    for z in levels[:-1]:
        dk = disk()
        dk.parent = root
        dk.location = (0, -0.03, z + t)
    return root


def usb_stick():
    root = empty("usb")
    box(0.5, 0.2, 0.1, mat("blue600"), bevel=0.035, at=(-0.09, 0, 0), parent=root)
    box(0.18, 0.13, 0.07, mat("metal", rough=0.35, metallic=0.3), bevel=0.008, at=(0.25, 0, 0.015), parent=root)
    for y in (-0.03, 0.03):
        box(0.05, 0.03, 0.03, mat("slate"), bevel=0.003, at=(0.30, y, 0.03), parent=root)
    cyl(0.02, 0.008, mat("white", emission=0.6), parent=root, at=(-0.26, 0, 0.1))
    return root


def cloud(scale=1.0, alpha_tone=None):
    """Smooth cloud (metaball union, flattened bottom), floating a little above the floor."""
    root = empty("cloud")
    m = mat(alpha_tone or "white", rough=0.55, sheen=0.35)
    els = [(-0.36, 0.0, 0.22, 0.30), (-0.05, 0.02, 0.34, 0.40), (0.34, -0.02, 0.24, 0.30),
           (-0.2, -0.05, 0.14, 0.26), (0.12, -0.06, 0.14, 0.28), (0.0, 0.0, -0.55, -0.72)]
    mb = metaball(els, m, parent=root, name="cloud", res=0.025)
    mb.location = (0, 0, 0.0)
    root.scale = (scale,) * 3
    return root


def bucket():
    """S3-style bucket: tapered body, blue rim, light opening."""
    root = empty("bucket")
    cyl(0.37, 0.66, mat("paper"), r2=0.45, bevel=0.012, parent=root)
    cyl(0.47, 0.06, mat("blue300"), bevel=0.012, parent=root, at=(0, 0, 0.64))
    cyl(0.42, 0.012, mat("blue100"), parent=root, at=(0, 0, 0.70))
    cyl(0.4, 0.05, mat("blue300"), r2=0.405, parent=root, at=(0, 0, 0.26))
    return root


def archive():
    """Cold archive: box with a lid and a snowflake on the front."""
    root = empty("archive")
    box(0.8, 0.6, 0.38, mat("paper"), bevel=0.025, parent=root)
    box(0.84, 0.64, 0.1, mat("blue100"), bevel=0.025, at=(0, 0, 0.385), parent=root, name="lid")
    sf = empty("snow", root)
    sf.location = (0, -0.305, 0.2)
    snowflake(sf, 0.13, 0.011)
    return root


def snowflake(parent, L, r):
    """Six-armed snowflake in the XZ plane (facing -Y), centred on the parent."""
    m = mat("blue300")
    for k in range(3):
        a = math.radians(90 + 60 * k)
        d = Vector((math.cos(a), 0, math.sin(a)))
        capsule(-d * L, d * L, r, m, parent)
        for sgn in (1, -1):
            tip = d * L * sgn * 0.78
            for side in (1, -1):
                b = a + side * math.radians(40) * sgn
                e = Vector((math.cos(b), 0, math.sin(b))) * L * 0.3
                tube(tip, tip + e, r * 0.8, m, parent)


def key(scale=1.0, upright=True):
    """Gold key icon: ring left, shaft to +X, teeth down. Built in the XY plane
    (use with billboard()); upright=True stands it in the XZ plane facing -Y."""
    root = empty("key")
    g = gold()
    torus(0.095, 0.03, g, parent=root, at=(-0.19, 0, 0))
    capsule((-0.1, 0, 0), (0.30, 0, 0), 0.03, g, root)
    plate(0.05, 0.09, 0.06, 0.01, g, parent=root, cx=0.17, cy=-0.045, z0=-0.03)
    plate(0.05, 0.07, 0.06, 0.01, g, parent=root, cx=0.27, cy=-0.035, z0=-0.03)
    if upright:
        for ch in list(root.children):
            ch.matrix_parent_inverse = Matrix.Rotation(math.radians(90), 4, "X")
    root.scale = (scale,) * 3
    return root


def padlock(scale=1.0, body="blue600"):
    """Padlock standing on its base, keyhole facing -Y."""
    root = empty("padlock")
    plate(0.34, 0.27, 0.16, 0.06, mat(body), parent=root, cy=0.135, z0=-0.08).rotation_euler = (math.radians(90), 0, 0)
    sh = empty("shackle", root)
    m = mat("blue900", rough=0.4)
    R, r = 0.1, 0.028
    segs = 16
    pts = [Vector((R * math.cos(math.pi * i / segs), 0, 0.27 + R * math.sin(math.pi * i / segs))) for i in range(segs + 1)]
    for a, b in zip(pts, pts[1:]):
        tube(a, b, r, m, sh, segs=16, caps=False)
    for i in range(1, segs):
        sphere(r, m, at=pts[i], parent=sh)
    tube((-R, 0, 0.27), (-R, 0, 0.2), r, m, sh)
    tube((R, 0, 0.27), (R, 0, 0.2), r, m, sh)
    sphere(r, m, at=(-R, 0, 0.27), parent=sh)
    sphere(r, m, at=(R, 0, 0.27), parent=sh)
    cyl(0.03, 0.012, mat("white"), parent=root, at=(0, -0.082, 0.16), axis="Y")
    box(0.03, 0.012, 0.06, mat("white"), bevel=0.004, at=(0, -0.082, 0.085), parent=root)
    root.scale = (scale,) * 3
    return root


def folder(open_blocks=True, scale=1.0):
    """Upright folder facing -Y: back board with a tab, front cover, ciphertext
    blocks sandwiched between them and peeking out over the cover."""
    root = empty("folder")
    back = prism([(-0.72, 0), (0.72, 0), (0.72, 0.66), (-0.14, 0.66), (-0.22, 0.76), (-0.72, 0.76)],
                 0.03, mat("paper"), bevel=0.012, parent=root)
    back.rotation_euler = (math.radians(90), 0, 0)
    back.location = (0, 0.08, 0)
    front = plate(1.44, 0.56, 0.03, 0.04, mat("blue100"), parent=root, cy=0.28)
    front.rotation_euler = (math.radians(90), 0, 0)
    front.location = (0, -0.05, 0)
    box(1.40, 0.12, 0.5, mat("light"), bevel=0.01, at=(0, 0.02, 0), parent=root, name="pages")
    if open_blocks:
        g = empty("grid", root)
        g.location = (0, 0.0, 0.5)
        cipher_blocks(g, 9, 2, s=0.085, g=0.045, h=0.03, plane="xz")
    root.scale = (scale,) * 3
    return root


def house(scale=1.0):
    root = empty("house")
    box(0.7, 0.6, 0.46, mat("paper"), bevel=0.02, parent=root)
    roof = prism([(-0.46, 0), (0.46, 0), (0.0, 0.36)], 0.72, mat("blue300"), bevel=0.015, parent=root)
    roof.rotation_euler = (math.radians(90), 0, 0)
    roof.location = (0, 0.36, 0.45)
    plate(0.18, 0.26, 0.02, 0.02, mat("blue600"), parent=root, cy=0.13, cx=0, z0=-0.31).rotation_euler = (math.radians(90), 0, 0)
    for x in (-0.22, 0.22):
        plate(0.14, 0.14, 0.02, 0.015, mat("blue100"), parent=root, cx=x, cy=0.3, z0=-0.31).rotation_euler = (math.radians(90), 0, 0)
    root.scale = (scale,) * 3
    return root


def flame(scale=1.0, at=(0, 0, 0), parent=None):
    """Stylised flame: a teardrop (sphere + cone) with a lighter core."""
    root = empty("flame", parent)
    root.location = at
    for m, sc, off in ((mat("red", rough=0.5), 1.0, (0, 0, 0)), (mat("redlight", rough=0.5), 0.55, (0.0, -0.07, 0.0))):
        sphere(0.16 * sc, m, at=(off[0], off[1], off[2] + 0.16 * sc), parent=root, scale=(1, 1, 1.1))
        cone(0.158 * sc, 0.3 * sc, m, at=(off[0], off[1], off[2] + 0.19 * sc), parent=root)
    root.rotation_euler = (0, math.radians(-8), 0)
    root.scale = (scale,) * 3
    return root


def plane(scale=1.0):
    """Small stylised aeroplane heading +X."""
    root = empty("plane")
    m = mat("blue300")
    sphere(0.07, m, at=(0, 0, 0), parent=root, scale=(4.2, 1, 1))
    wing = prism([(-0.08, -0.55), (0.14, -0.55), (0.06, 0.55), (-0.08, 0.55)], 0.03, m, bevel=0.01, parent=root)
    wing.location = (-0.02, 0, -0.02)
    tail = prism([(-0.3, -0.18), (-0.2, -0.18), (-0.24, 0.18), (-0.3, 0.18)], 0.025, m, bevel=0.008, parent=root)
    tail.location = (0, 0, 0.0)
    fin = prism([(-0.3, 0), (-0.18, 0), (-0.24, 0.16), (-0.3, 0.16)], 0.025, m, bevel=0.008, parent=root)
    fin.rotation_euler = (math.radians(90), 0, 0)
    fin.location = (0, 0.012, 0.02)
    root.scale = (scale,) * 3
    return root


def card(w, h, r=0.12, tone="white", t=0.02):
    """Floating UI card facing the camera: w, h in grid px (use with billboard())."""
    root = empty("card")
    plate(w * PX, h * PX, t, r * PX, mat(tone, rough=0.5, sheen=0.1, emission=CARD_EMISSION), parent=root, z0=-t)
    return root


def badge(kind="ok", r=11.5):
    """Round check (green) or cross (red) badge facing the camera (use with billboard())."""
    root = empty("badge")
    rr = r * PX
    cyl(rr, 0.012, mat("white"), parent=root, at=(0, 0, -0.012))
    col = {"ok": "green", "x": "red"}[kind]
    cyl(rr * 0.83, 0.01, mat(col, rough=0.45), parent=root, at=(0, 0, 0.0))
    w = mat("white")
    tr = 0.012 * r / 11.5
    if kind == "ok":
        capsule((-0.045 * r / 11.5, 0.0, 0.012), (-0.012 * r / 11.5, -0.034 * r / 11.5, 0.012), tr, w, root)
        capsule((-0.012 * r / 11.5, -0.034 * r / 11.5, 0.012), (0.05 * r / 11.5, 0.036 * r / 11.5, 0.012), tr, w, root)
    else:
        s = 0.036 * r / 11.5
        capsule((-s, -s, 0.012), (s, s, 0.012), tr, w, root)
        capsule((-s, s, 0.012), (s, -s, 0.012), tr, w, root)
    return root


def seal(r=19):
    """Round seal: white disc, blue face and a thin ring (initials composed later)."""
    root = empty("seal")
    rr = r * PX
    cyl(rr, 0.012, mat("white"), parent=root, at=(0, 0, -0.012))
    cyl(rr * 0.79, 0.014, mat("blue600"), parent=root, at=(0, 0, 0))
    ring = torus(rr * 0.58, 0.006, mat("#8aa9ff"), parent=root, at=(0, 0, 0.014))
    return root


def cloud_icon(scale=1.0, tone="blue300"):
    """Flat cloud glyph in the XY plane (for cards, with on_card())."""
    root = empty("cloudicon")
    m = mat(tone, rough=0.5)
    for x, z, r in ((-0.11, 0.0, 0.085), (0.0, 0.035, 0.11), (0.12, 0.0, 0.08)):
        cyl(r, 0.014, m, parent=root, at=(x, z, 0))
    plate(0.34, 0.1, 0.014, 0.05, m, parent=root, cy=-0.04)
    root.scale = (scale,) * 3
    return root


def file_icon(scale=1.0):
    """Small document sheet (standing, facing camera when used with billboard())."""
    root = empty("file")
    poly = [(-0.14, -0.2), (0.14, -0.2), (0.14, 0.1), (0.04, 0.2), (-0.14, 0.2)]
    prism(poly, 0.012, mat("#e6ecf9"), bevel=0.005, parent=root)
    prism([(0.04, 0.1), (0.14, 0.1), (0.04, 0.2)], 0.014, mat("blue300"), bevel=0.004, parent=root)
    for i, L in enumerate((0.16, 0.12, 0.16)):
        plate(L, 0.022, 0.012, 0.01, mat("blue300"), parent=root, cx=-0.14 + 0.04 + L / 2, cy=0.02 - i * 0.07, z0=0.012)
    root.scale = (scale,) * 3
    return root


def folder_icon(scale=1.0):
    root = empty("ficon")
    poly = [(-0.2, -0.14), (0.2, -0.14), (0.2, 0.1), (-0.02, 0.1), (-0.06, 0.15), (-0.2, 0.15)]
    prism(poly, 0.012, mat("blue100"), bevel=0.005, parent=root)
    plate(0.4, 0.2, 0.014, 0.02, mat("blue300"), parent=root, cy=-0.04, z0=0.004)
    root.scale = (scale,) * 3
    return root


def camera_icon():
    root = empty("cam")
    cyl(0.14, 0.012, mat("white"), parent=root, at=(0, 0, -0.012))
    plate(0.16, 0.11, 0.02, 0.025, mat("blue600"), parent=root, cy=-0.005)
    plate(0.07, 0.03, 0.02, 0.01, mat("blue900"), parent=root, cy=0.065)
    cyl(0.03, 0.008, mat("white"), parent=root, at=(0, 0.0, 0.02))
    cyl(0.014, 0.006, mat("blue600"), parent=root, at=(0, 0.0, 0.028))
    return root


def dock():
    """Small USB dock with three ports."""
    root = empty("dock")
    box(0.56, 0.24, 0.1, mat("paper"), bevel=0.02, parent=root)
    for x in (-0.16, 0.0, 0.16):
        box(0.09, 0.02, 0.05, mat("slate"), bevel=0.004, at=(x, -0.125, 0.03), parent=root)
    return root


def pedestal(r=0.76, h=0.12):
    root = empty("pedestal")
    cyl(r, h, mat("blue600", rough=0.4), bevel=0.03, parent=root)
    torus(r * 0.98, 0.012, mat("#7f9cff"), parent=root, at=(0, 0, h))
    return root


def storage_panel(cols=7, rows=6, w=1.4, h=1.26):
    """Standing slab (facing -Y) covered with ciphertext blocks: a shared storage."""
    root = empty("storage")
    box(w, 0.14, h, mat("paper"), bevel=0.03, parent=root)
    g = empty("grid", root)
    g.location = (0, -0.07, h / 2)
    cipher_blocks(g, cols, rows, s=0.11, g=0.05, h=0.025, plane="xz")
    return root


def framed_card(w, h, r=14, frame="blue600", t=0.02, border=3):
    """Floating card with a coloured frame (grid px), facing the camera."""
    root = empty("cardf")
    plate((w + 2 * border) * PX, (h + 2 * border) * PX, t, (r + border) * PX, mat(frame, rough=0.45), parent=root, z0=-t - 0.004)
    plate(w * PX, h * PX, t, r * PX, mat("white", rough=0.5, sheen=0.1, emission=CARD_EMISSION), parent=root, z0=-t)
    return root


def bar(w, h, tone="dark", r=8, t=0.03):
    """Dark menu bar / plain slab facing the camera (grid px)."""
    root = empty("bar")
    plate(w * PX, h * PX, t, r * PX, mat(tone, rough=0.5), parent=root, z0=-t)
    return root


def dot(r_px, tone="blue600", emission=0.0):
    root = empty("dot")
    cyl(r_px * PX, 0.012, mat(tone, rough=0.45, emission=emission), parent=root)
    return root


def tray_icon():
    root = empty("tray")
    plate(0.16, 0.16, 0.014, 0.04, mat("blue600"), parent=root)
    cyl(0.03, 0.01, mat("white"), parent=root, at=(0, 0, 0.014))
    return root


def sparkle():
    """Assistant badge: blue disc with a white four-point star."""
    import math as _m
    root = empty("sparkle")
    cyl(0.1, 0.012, mat("blue600"), parent=root)
    pts = []
    for i in range(8):
        a = _m.pi / 4 * i
        r = 0.062 if i % 2 == 0 else 0.018
        pts.append((r * _m.cos(a), r * _m.sin(a)))
    prism(pts, 0.01, mat("white"), parent=root, z0=0.012)
    return root


def ring(R_px, r=0.006, tone="gold"):
    root = empty("ring")
    torus(R_px * PX, r, gold() if tone == "gold" else mat(tone), parent=root)
    return root


# ---------------------------------------------------------------- links
def _bezier(p0, p1, p2, p3, n):
    out = []
    for i in range(n + 1):
        t = i / n
        a, b = (1 - t), t
        x = a ** 3 * p0[0] + 3 * a * a * b * p1[0] + 3 * a * b * b * p2[0] + b ** 3 * p3[0]
        y = a ** 3 * p0[1] + 3 * a * a * b * p1[1] + 3 * a * b * b * p2[1] + b ** 3 * p3[1]
        out.append((x, y))
    return out


def link(points, h=0.3, dash=6.0, gap=5.0, r=0.011, tone="blue300", arrows=("end",), solid=False, lift=0.0):
    """Dashed (or solid) link along a screen-space path, floating at height h.
    points: 2 grid points for a straight line, 4 for a cubic Bezier, 3 for a quadratic."""
    root = empty("link")
    m = mat(tone, rough=0.45)
    if len(points) == 2:
        poly = _bezier(points[0], points[0], points[1], points[1], 48)
    elif len(points) == 3:
        p0, c, p3 = points
        poly = _bezier(p0, (p0[0] + 2 / 3 * (c[0] - p0[0]), p0[1] + 2 / 3 * (c[1] - p0[1])),
                       (p3[0] + 2 / 3 * (c[0] - p3[0]), p3[1] + 2 / 3 * (c[1] - p3[1])), p3, 64)
    else:
        poly = _bezier(*points, 64)
    world = [ground_point(x, y, h + lift) + Vector((0, 0, h + lift)) for x, y in poly]
    # Arc-length parametrise, then lay dashes.
    seg = [(world[i + 1] - world[i]).length for i in range(len(world) - 1)]
    total = sum(seg)
    head = 0.09 if arrows else 0.0

    def at(s):
        acc = 0.0
        for i, L in enumerate(seg):
            if acc + L >= s or i == len(seg) - 1:
                t = (s - acc) / L if L else 0
                return world[i].lerp(world[i + 1], t)
            acc += L
        return world[-1]

    start = head if "start" in arrows else 0.0
    end = total - (head if "end" in arrows else 0.0)
    if solid:
        pts = [at(start + (end - start) * i / 40) for i in range(41)]
        for a, b in zip(pts, pts[1:]):
            tube(a, b, r, m, root, segs=12, caps=False)
        for p in pts:
            sphere(r, m, at=p, parent=root)
    else:
        s = start
        D, G = dash * PX, gap * PX
        while s < end - 0.01:
            e = min(s + D, end)
            capsule(at(s), at(e), r, m, root)
            s = e + G
    if "end" in arrows:
        d = (at(total) - at(total - 0.05)).normalized()
        cone(0.035, head, m, at=at(total - head), parent=root, direction=d)
    if "start" in arrows:
        d = (at(0) - at(0.05)).normalized()
        cone(0.035, head, m, at=at(head), parent=root, direction=d)
    return root


# ---------------------------------------------------------------- render
def render(path: str):
    scene = bpy.context.scene
    scene.render.filepath = path
    bpy.ops.render.render(write_still=True)
    return path
