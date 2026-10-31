"""Draws the 512 px store icon (fastlane/metadata/android/en-US/images/icon.png) from the app's own globe icon
(res/drawable/ic_globe.xml on the res/values/colors.xml blue). Needs Pillow; run it again if the icon changes."""

from pathlib import Path

from PIL import Image, ImageDraw

SIZE, SUPER = 512, 4  # drawn 4x larger, then shrunk, for smooth edges
BLUE, WHITE = (0x15, 0x65, 0xC0, 255), (255, 255, 255, 255)
OUT = Path(__file__).resolve().parent.parent / "fastlane" / "metadata" / "android" / "en-US" / "images" / "icon.png"


def main() -> None:
    big = SIZE * SUPER
    scale = big / 108  # the vector's viewport is 108 x 108
    image = Image.new("RGBA", (big, big), BLUE)
    draw = ImageDraw.Draw(image)
    width = round(3 * scale)

    def box(cx, cy, rx, ry):
        return [(cx - rx) * scale, (cy - ry) * scale, (cx + rx) * scale, (cy + ry) * scale]

    draw.ellipse(box(54, 54, 22, 22), outline=WHITE, width=width)  # the globe
    draw.ellipse(box(54, 54, 10, 22), outline=WHITE, width=width)  # a meridian
    for y, x0, x1 in ((54, 32, 76), (43, 35.5, 72.5), (65, 35.5, 72.5)):  # the equator and two parallels
        draw.line([(x0 * scale, y * scale), (x1 * scale, y * scale)], fill=WHITE, width=width)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    image.resize((SIZE, SIZE), Image.LANCZOS).save(OUT)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
