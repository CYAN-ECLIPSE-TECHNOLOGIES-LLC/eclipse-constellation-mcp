#!/usr/bin/env python3
"""Generate icon-512.png — brand system SS6: eclipse motif on the navy
field (#0d1b2a), one per-product glyph. Constellation's glyph is a
star cluster: a crescent eclipse ring + a scatter of stars read as one
figure. PIL only; deterministic."""
from PIL import Image, ImageDraw

S = 512
NAVY = (13, 27, 42, 255)
STOPS = [(15, 246, 247), (0, 212, 255), (123, 44, 191)]  # cyan->blue->purple


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)


def grad(t):
    return lerp(STOPS[0], STOPS[1], t * 2) if t < 0.5 else \
        lerp(STOPS[1], STOPS[2], (t - 0.5) * 2)


def star(d, cx, cy, r, color):
    d.polygon([(cx, cy - r), (cx + r * 0.28, cy - r * 0.28), (cx + r, cy),
               (cx + r * 0.28, cy + r * 0.28), (cx, cy + r),
               (cx - r * 0.28, cy + r * 0.28), (cx - r, cy),
               (cx - r * 0.28, cy - r * 0.28)], fill=color)


def main():
    img = Image.new("RGBA", (S, S), NAVY)
    d = ImageDraw.Draw(img)
    # Eclipse ring: gradient arc segments, lower-left.
    box = [86, 150, 350, 414]
    for i in range(72):
        t = i / 72
        d.arc(box, start=i * 5, end=i * 5 + 6, fill=grad(t), width=17)
    d.ellipse([150, 214, 286, 350], fill=NAVY)  # occluding body
    # Star cluster: the fleet, read as one figure.
    stars = [(392, 128, 30), (330, 92, 18), (448, 208, 20), (368, 196, 13),
             (424, 300, 15), (316, 268, 10), (458, 116, 11)]
    for j, (x, y, r) in enumerate(stars):
        star(d, x, y, r, grad(j / max(1, len(stars) - 1)))
    d.line([(392, 128), (330, 92)], fill=(0, 212, 255, 160), width=3)
    d.line([(392, 128), (448, 208)], fill=(0, 212, 255, 160), width=3)
    d.line([(448, 208), (424, 300)], fill=(123, 44, 191, 160), width=3)
    img.save("icon-512.png")
    print("wrote icon-512.png", img.size, img.mode)


if __name__ == "__main__":
    main()
