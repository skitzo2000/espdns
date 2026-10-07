"""
dns2 enclosure: Guition JC-ESP32P4-M3-DEV (92 x 62 mm).

Run headless:   freecadcmd -c "exec(open('enclosure/dns2_case.py').read())"
(or `make enclosure`). Writes STL/STEP/FCStd to enclosure/out/ and fails if the case
collides with the board model.

No screws: printed pins on the standoffs locate the board through its mounting holes, the
lid's tubes come down over the pins to hold it, and the lid snaps on with a skirt around
three sides (a bead in the skirt clicks into a groove in the walls).

Coordinates: X along the 92 mm edge, with the port edge at +X. Y along the 62 mm edge,
with Y=0 at the RJ45 corner (the photo's bottom edge). Z up, with the case floor at Z=0.
Port positions were read off Guition's product drawing and photo (±0.5-1 mm). Check them
with the fit-test coupon before printing the full case.
"""
import math
import os

import FreeCAD as App
import MeshPart
import Part

V = App.Vector
OUT = os.environ.get("DNS2_CASE_OUT", os.path.join(os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else "enclosure", "out"))
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------- board
PCB_L, PCB_W, PCB_T = 92.0, 62.0, 1.6
HOLES = [(2.8, 2.8), (64.8, 2.8), (2.8, 59.2), (64.8, 59.2)]   # 62 x 56.4 mm spacing
BOARD_HOLE_D = 2.7                                               # ASSUMED (M3 won't pass): measure and set

# Ports on the +X edge. y_from_top is measured from the photo's top edge; model y = 62 - that.
USB_W, USB_H, USB_DEPTH = 8.94, 3.26, 7.35     # USB-C receptacle
USB_PROUD = 1.6                                # sticks out past the PCB edge
USB_CENTERS_FROM_TOP = {"USB3 (HS OTG)": 6.0, "USB2 (USB/JTAG)": 16.6, "USB1 (CH340)": 27.5}
RJ45_Y_FROM_TOP = (44.2, 62.9)                 # spans past the PCB's bottom edge
RJ45_PROUD = 3.0
RJ45_H = 13.5                                  # above the PCB top
RJ45_DEPTH = 21.3
HEADER = dict(x=(0.3, 5.3), y_from_top=(10.0, 52.0), h=8.5)   # left pin header (unused)

# ---------------------------------------------------------------- case
WALL = 2.0
WALL_PORT = 1.6          # thinner port wall, so the USB-C faces sit ~flush
FLOOR = 2.0
LID = 2.0
GAP = 1.25               # PCB-to-wall clearance on the closed sides
GAP_PORT = 0.6           # PCB edge to the port wall's inside face
GAP_RJ45_SIDE = 1.6      # the RJ45 sticks out past the Y=0 board edge
STANDOFF_H = 4.0         # clears through-hole pins on the underside (3 mm keep-out + 1 mm)
STANDOFF_D = 6.0
PIN_D = BOARD_HOLE_D - 0.3   # locating pin through the board hole (0.15 mm per side)
PIN_ABOVE = 1.4          # how far the pin sticks up above the PCB (into the lid tube)
PIN_TIP = 0.6            # chamfered tip height

TOP_CLEAR = 2.05         # above the tallest part (RJ45)
CORNER_R = 3.0
USB_OPEN_MARGIN = 0.85   # clearance around every USB-C receptacle
USB_OPEN_MARGIN_Z = 0.9
USB_OPEN_R = 1.0         # corner radius of the opening
# At a 10.6 mm pitch, generous separate openings would merge anyway: cut one slot across all three.
RJ45_OPEN_MARGIN = 0.9
TUBE_D = 5.0             # lid tubes that come down over the pins to hold the PCB
TUBE_BORE = PIN_D + 0.5  # socket for the pin tip
TUBE_GAP = 0.2           # stop short of the PCB so the lid always seats on the walls
SKIRT_T, SKIRT_H = 1.4, 5.0      # lid skirt around the three closed walls
SKIRT_CLEAR = 0.2                 # skirt to wall
BEAD, BEAD_H = 0.5, 1.0           # bead on the skirt's inside (0.3 mm catch after the clearance)
BEAD_Z = 2.8                      # bead centre below the wall top
GROOVE, GROOVE_H = 0.6, 1.6       # matching groove in the wall's outside
LEAD_IN = 0.6                     # chamfer on the wall's outer top edge so the bead rides on
VENT_W, VENT_L, VENT_PITCH = 2.0, 22.0, 4.5
LABEL = os.environ.get("DNS2_CASE_LABEL", "espDNS")  # make enclosure CASE_LABEL=... (the node's name, address)
LABEL_SIZE, LABEL_Y = 4.5, 50.0   # clear band between the vents and the back tubes
FONT = "/nix/store/71mxn2pyq807r32qsd2mdszkajhlb39q-dejavu-fonts-2.37/share/fonts/truetype/DejaVuSans-Bold.ttf"
CLEAR_MIN = 0.4          # every board part must be at least this far from the case
HARDWARE = "none (printed pins + snap lid)"

# ---------------------------------------------------------------- derived
Z_PCB = FLOOR + STANDOFF_H
Z_PCB_TOP = Z_PCB + PCB_T
Z_WALL_TOP = Z_PCB_TOP + RJ45_H + TOP_CLEAR
X_IN0, X_IN1 = -GAP, PCB_L + GAP_PORT
Y_IN0, Y_IN1 = -GAP_RJ45_SIDE, PCB_W + GAP
X0, X1 = X_IN0 - WALL, X_IN1 + WALL_PORT
Y0, Y1 = Y_IN0 - WALL, Y_IN1 + WALL
my = lambda y_from_top: PCB_W - y_from_top   # photo coordinates -> model Y


def box(x0, x1, y0, y1, z0, z1):
    return Part.makeBox(x1 - x0, y1 - y0, z1 - z0, V(x0, y0, z0))


def rounded_box(x0, x1, y0, y1, z0, z1, r):
    b = box(x0, x1, y0, y1, z0, z1)
    vert = [e for e in b.Edges if abs(e.BoundBox.ZLength - (z1 - z0)) < 1e-6
            and e.BoundBox.XLength < 1e-6 and e.BoundBox.YLength < 1e-6]
    return b.makeFillet(r, vert) if r > 0 else b


def cyl(x, y, z0, z1, d):
    return Part.makeCylinder(d / 2, z1 - z0, V(x, y, z0))


def slot_x(x0, x1, yc, zc, w, h, r):
    """A rounded-rectangle opening through a wall perpendicular to X: w along Y, h along Z."""
    core = box(x0, x1, yc - w / 2 + r, yc + w / 2 - r, zc - h / 2, zc + h / 2)
    core = core.fuse(box(x0, x1, yc - w / 2, yc + w / 2, zc - h / 2 + r, zc + h / 2 - r))
    for sy in (-1, 1):
        for sz in (-1, 1):
            core = core.fuse(Part.makeCylinder(r, x1 - x0, V(x0, yc + sy * (w / 2 - r), zc + sz * (h / 2 - r)),
                                               V(1, 0, 0)))
    return core


# ---------------------------------------------------------------- board model (fit check)
def board_model():
    pcb = box(0, PCB_L, 0, PCB_W, Z_PCB, Z_PCB_TOP)
    for x, y in HOLES:
        pcb = pcb.cut(cyl(x, y, Z_PCB - 1, Z_PCB_TOP + 1, BOARD_HOLE_D))
    parts = {"pcb": pcb}
    for name, yt in USB_CENTERS_FROM_TOP.items():
        yc = my(yt)
        parts[name] = box(PCB_L + USB_PROUD - USB_DEPTH, PCB_L + USB_PROUD, yc - USB_W / 2, yc + USB_W / 2,
                          Z_PCB_TOP, Z_PCB_TOP + USB_H)
    ya, yb = sorted(my(v) for v in RJ45_Y_FROM_TOP)
    parts["rj45"] = box(PCB_L + RJ45_PROUD - RJ45_DEPTH, PCB_L + RJ45_PROUD, ya, yb, Z_PCB_TOP, Z_PCB_TOP + RJ45_H)
    ha, hb = sorted(my(v) for v in HEADER["y_from_top"])
    parts["header"] = box(HEADER["x"][0], HEADER["x"][1], ha, hb, Z_PCB_TOP, Z_PCB_TOP + HEADER["h"])
    # generic 3 mm keep-out under the board for through-hole pins, except where the standoffs sit
    keep = box(0.5, PCB_L - 0.5, 0.5, PCB_W - 0.5, Z_PCB - 3.0, Z_PCB)
    for x, y in HOLES:
        keep = keep.cut(cyl(x, y, Z_PCB - 4, Z_PCB + 1, STANDOFF_D + 0.6))
    parts["underside pins"] = keep
    return parts


# ---------------------------------------------------------------- base
def port_cuts():
    cuts = []
    xw0, xw1 = X_IN1 - 0.5, X1 + 0.5
    zc = Z_PCB_TOP + USB_H / 2
    ys = [my(yt) for yt in USB_CENTERS_FROM_TOP.values()]
    ya, yb = min(ys) - USB_W / 2 - USB_OPEN_MARGIN, max(ys) + USB_W / 2 + USB_OPEN_MARGIN
    cuts.append(slot_x(xw0, xw1, (ya + yb) / 2, zc, yb - ya, USB_H + 2 * USB_OPEN_MARGIN_Z, USB_OPEN_R))
    ya, yb = sorted(my(v) for v in RJ45_Y_FROM_TOP)
    m = RJ45_OPEN_MARGIN
    cuts.append(box(xw0, xw1, ya - m, yb + m, Z_PCB - 0.5, Z_PCB_TOP + RJ45_H + m))
    return cuts


def make_base(coupon=False):
    top = Z_WALL_TOP if not coupon else Z_PCB_TOP + RJ45_H + TOP_CLEAR
    floor = FLOOR
    outer = rounded_box(X0, X1, Y0, Y1, 0, top, CORNER_R)
    if not coupon:
        top_edges = [e for e in outer.Edges if abs(e.BoundBox.ZMin - top) < 1e-6 and abs(e.BoundBox.ZMax - top) < 1e-6]
        outer = outer.makeChamfer(LEAD_IN, top_edges)
    base = outer.cut(box(X_IN0, X_IN1, Y_IN0, Y_IN1, floor, top + 1))
    if not coupon:
        # snap groove around the three closed walls (stops short of the port wall's corners)
        zc = top - BEAD_Z
        band = rounded_box(X0 - 1, X1 + 1, Y0 - 1, Y1 + 1, zc - GROOVE_H / 2, zc + GROOVE_H / 2, CORNER_R + 1).cut(
            rounded_box(X0 + GROOVE, X1 - GROOVE, Y0 + GROOVE, Y1 - GROOVE, zc - GROOVE_H, zc + GROOVE_H,
                        CORNER_R - GROOVE))
        base = base.cut(band.common(box(X0 - 2, X1 - CORNER_R - 1.0, Y0 - 2, Y1 + 2, 0, top)))
    if coupon:
        # keep only the floor, the standoffs, the port wall and short wall stubs for stiffness
        keep = box(X0 - 1, X1 + 1, Y0 - 1, Y1 + 1, 0, floor).fuse(box(X_IN1 - 8, X1 + 1, Y0 - 1, Y1 + 1, 0, top + 1))
        base = base.common(keep)
        floor_cut = []
        for x0, x1, y0, y1 in ((8, 58, 8, 54), (70, 84, 22, 54)):   # lighten the floor
            floor_cut.append(box(x0, x1, y0, y1, -1, floor + 1))
        for c in floor_cut:
            base = base.cut(c)
    for x, y in HOLES:
        base = base.fuse(cyl(x, y, floor - 0.01, Z_PCB, STANDOFF_D))
        # locating pin with a chamfered tip
        base = base.fuse(cyl(x, y, Z_PCB - 0.01, Z_PCB_TOP + PIN_ABOVE - PIN_TIP, PIN_D))
        base = base.fuse(Part.makeCone(PIN_D / 2, PIN_D / 2 - 0.4, PIN_TIP, V(x, y, Z_PCB_TOP + PIN_ABOVE - PIN_TIP)))
    for c in port_cuts():
        base = base.cut(c)
    if not coupon:
        # low vents in the long walls, under the PCB
        for x in range(12, 82, 7):
            for yw0, yw1 in ((Y0 - 1, Y_IN0 + 0.5), (Y_IN1 - 0.5, Y1 + 1)):
                base = base.cut(box(x, x + 2.5, yw0, yw1, FLOOR + 1.0, Z_PCB - 1.0))
    return base.removeSplitter()


# ---------------------------------------------------------------- lid
def make_lid():
    z0, z1 = Z_WALL_TOP, Z_WALL_TOP + LID
    o_in, o_out = SKIRT_CLEAR, SKIRT_CLEAR + SKIRT_T
    x_cut = X1 - CORNER_R - 1.0                 # the skirt stops before the port-wall corners
    # plate: out to the skirt on three sides, flush with the port wall
    lid = rounded_box(X0 - o_out, X1 + o_out, Y0 - o_out, Y1 + o_out, z0, z1, CORNER_R + o_out).common(
        box(X0 - o_out - 1, X1, Y0 - o_out - 1, Y1 + o_out + 1, z0 - 1, z1 + 1))
    skirt = rounded_box(X0 - o_out, X1 + o_out, Y0 - o_out, Y1 + o_out, z0 - SKIRT_H, z0 + 0.01, CORNER_R + o_out).cut(
        rounded_box(X0 - o_in, X1 + o_in, Y0 - o_in, Y1 + o_in, z0 - SKIRT_H - 1, z0 + 1, CORNER_R + o_in))
    zc = z0 - BEAD_Z
    bead = rounded_box(X0 - o_in, X1 + o_in, Y0 - o_in, Y1 + o_in, zc - BEAD_H / 2, zc + BEAD_H / 2, CORNER_R + o_in).cut(
        rounded_box(X0 - o_in + BEAD, X1 + o_in - BEAD, Y0 - o_in + BEAD, Y1 + o_in - BEAD, zc - BEAD_H, zc + BEAD_H,
                    CORNER_R + o_in - BEAD))
    lid = lid.fuse(skirt.fuse(bead).common(box(X0 - o_out - 1, x_cut, Y0 - o_out - 1, Y1 + o_out + 1, z0 - SKIRT_H - 1, z0 + 0.02)))
    # tubes down over the pins, holding the PCB
    for x, y in HOLES:
        lid = lid.fuse(cyl(x, y, Z_PCB_TOP + TUBE_GAP, z0 + 0.01, TUBE_D))
        lid = lid.cut(cyl(x, y, Z_PCB_TOP - 1, Z_PCB_TOP + PIN_ABOVE + 0.5, TUBE_BORE))
    # vents over the module and the regulators
    for i in range(9):
        x = 14 + i * VENT_PITCH
        lid = lid.cut(box(x, x + VENT_W, 20, 20 + VENT_L, z0 - 1, z1 + 1))
    # engraved label along the front edge
    try:
        if LABEL and os.path.exists(FONT):
            chars = Part.makeWireString(LABEL, FONT, LABEL_SIZE, 0)
            faces = [Part.Face(w, "Part::FaceMakerBullseye") for w in chars if w]
            txt = Part.Compound(faces)
            bb = txt.BoundBox
            txt.translate(V((X0 + X1) / 2 - bb.Center.x, LABEL_Y - bb.Center.y, z1 - 0.6))
            engrave = txt.extrude(V(0, 0, 1.0))
            for x, y in HOLES:
                if engrave.common(cyl(x, y, z0 - 1, z1 + 1, TUBE_D + 2)).Volume > 0:
                    raise ValueError("label overlaps a tube; move LABEL_Y")
            lid = lid.cut(engrave)
    except Exception as e:  # a label is nice to have, never a blocker
        print("label skipped:", e)
    return lid.removeSplitter()


# ---------------------------------------------------------------- build + checks
def check(name, shape, board):
    bad = []
    for part, b in board.items():
        v = shape.common(b).Volume
        if v > 1e-3:
            bad.append(f"{part}: {v:.2f} mm^3")
    print(f"fit check {name}: " + ("OK" if not bad else "COLLIDES -> " + "; ".join(bad)))
    return not bad


board = board_model()
base = make_base()
lid = make_lid()
coupon = make_base(coupon=True)

def inflate(shape, m, z=True):
    b = shape.BoundBox
    return box(b.XMin - m, b.XMax + m, b.YMin - m, b.YMax + m, b.ZMin - (m if z else 0), b.ZMax + (m if z else 0))


# Clearance: grow each component by CLEAR_MIN (the PCB only sideways: it rests on the standoffs).
grown = {k: inflate(v, CLEAR_MIN, z=(k != "pcb")) for k, v in board.items() if k != "underside pins"}
for x, y in HOLES:   # the pins are meant to pass through the board holes
    grown["pcb"] = grown["pcb"].cut(cyl(x, y, Z_PCB - 1, Z_PCB_TOP + 1, BOARD_HOLE_D))
clear_ok = all([check(f"{n} +{CLEAR_MIN} mm clearance", shp, grown) for n, shp in (("base", base), ("lid", lid))])

pin_ok = PIN_D >= 2.0 and PIN_D <= BOARD_HOLE_D - 0.2 and TUBE_BORE < TUBE_D - 1.6
print(f"pin check: {PIN_D:.2f} mm pin in a {BOARD_HOLE_D:.2f} mm board hole, tube wall "
      f"{(TUBE_D - TUBE_BORE) / 2:.2f} mm -> " + ("OK" if pin_ok else "ADJUST"))
catch = BEAD - SKIRT_CLEAR
snap_ok = 0.2 <= catch <= 0.5 and GROOVE >= BEAD - SKIRT_CLEAR + 0.2 and WALL - GROOVE >= 1.2
print(f"snap check: {catch:.2f} mm catch, {GROOVE:.2f} mm groove, {WALL - GROOVE:.2f} mm wall left -> "
      + ("OK" if snap_ok else "ADJUST"))

overlap = lid.common(base).Volume   # closed lid must not intersect the base (bead sits in the groove)
mate_ok = overlap < 1e-3
print(f"fit check lid vs base: " + ("OK" if mate_ok else f"OVERLAP {overlap:.2f} mm^3"))

ok = all([check("base", base, board), check("lid", lid, board), check("coupon", coupon, board),
          clear_ok, pin_ok, snap_ok, mate_ok])

doc = App.newDocument("dns2_case")
for name, shp in (("base", base), ("lid", lid), ("coupon", coupon)):
    doc.addObject("Part::Feature", name).Shape = shp
    MeshPart.meshFromShape(Shape=shp, LinearDeflection=0.05, AngularDeflection=0.25).write(
        os.path.join(OUT, f"dns2_{name}.stl"))
    shp.exportStep(os.path.join(OUT, f"dns2_{name}.step"))
bm = Part.makeCompound(list(board.values()))
doc.addObject("Part::Feature", "board_model").Shape = bm
MeshPart.meshFromShape(Shape=bm, LinearDeflection=0.05).write(os.path.join(OUT, "board_model.stl"))
doc.saveAs(os.path.join(OUT, "dns2_case.FCStd"))

print(f"outside {X1 - X0 + SKIRT_CLEAR + SKIRT_T:.1f} x {Y1 - Y0 + 2 * (SKIRT_CLEAR + SKIRT_T):.1f} x {Z_WALL_TOP + LID:.1f} mm; "
      f"base {base.Volume / 1000:.1f} cm^3, lid {lid.Volume / 1000:.1f} cm^3, coupon {coupon.Volume / 1000:.1f} cm^3")
print("hardware:", HARDWARE)
print("RESULT:", "PASS" if ok else "FAIL")
if not ok:
    raise SystemExit(1)
