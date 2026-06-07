"""Generate TrustSphere PWA icons."""

from pathlib import Path


BRAND_NAVY = "#0B1F4E"
BRAND_GOLD = "#C9A84C"
BRAND_TEAL = "#006D77"
WHITE = "#FFFFFF"


def _load_font(size):
    from PIL import ImageFont

    candidates = [
        "arial.ttf",
        "Arial.ttf",
        "DejaVuSans-Bold.ttf",
        "calibrib.ttf",
    ]
    for font_name in candidates:
        try:
            return ImageFont.truetype(font_name, size=size)
        except IOError:
            continue
    return ImageFont.load_default()


def _shield_points(size, inset):
    top = inset
    left = inset
    right = size - inset
    bottom = size - inset
    center = size / 2
    return [
        (center, top),
        (right, top + size * 0.14),
        (right - size * 0.07, bottom - size * 0.28),
        (center, bottom),
        (left + size * 0.07, bottom - size * 0.28),
        (left, top + size * 0.14),
    ]


def _draw_icon(size, output_path):
    from PIL import Image, ImageDraw

    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    radius = max(int(size * 0.18), 16)
    margin = int(size * 0.04)
    draw.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=radius,
        fill=BRAND_NAVY,
    )

    outer_inset = int(size * 0.18)
    inner_inset = int(size * 0.28)
    draw.polygon(_shield_points(size, outer_inset), fill=BRAND_GOLD)
    draw.polygon(_shield_points(size, inner_inset), fill=BRAND_TEAL)

    font = _load_font(int(size * 0.42))
    text = "T"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (size - text_width) / 2 - bbox[0]
    y = (size - text_height) / 2 - bbox[1] - size * 0.02
    draw.text((x, y), text, fill=WHITE, font=font)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path, "PNG")


def generate_trustsphere_icon():
    """Create the 192px and 512px TrustSphere PWA icon files."""
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        print("[TrustSphere] Pillow is required to generate icons. Install it with: pip install pillow")
        return False

    output_dir = Path("app") / "static" / "img"
    _draw_icon(192, output_dir / "icon-192.png")
    _draw_icon(512, output_dir / "icon-512.png")
    print("[TrustSphere] Icons generated: icon-192.png (192x192), icon-512.png (512x512)")
    return True


if __name__ == "__main__":
    generate_trustsphere_icon()
