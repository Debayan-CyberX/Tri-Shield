"""Generate synthetic DEMO identity cards (not government templates, not real PII)."""

from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.validators import make_valid_aadhaar  # noqa: E402

OUT = Path(__file__).resolve().parent


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    names = ["segoeui.ttf", "SegoeUI.ttf", "arial.ttf", "Arial.ttf", "calibri.ttf"]
    if bold:
        names = ["segoeuib.ttf", "arialbd.ttf", "calibrib.ttf"] + names
    windir = Path("C:/Windows/Fonts")
    for name in names:
        path = windir / name
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def _qr(payload: dict, box: int = 7) -> Image.Image | None:
    try:
        import qrcode
    except ImportError:
        return None
    qr = qrcode.QRCode(border=1, box_size=box)
    qr.add_data(json.dumps(payload, separators=(",", ":")))
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


def _base(title: str, accent: tuple[int, int, int], size=(1100, 700)) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", size, (248, 250, 252))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, size[0], 88], fill=accent)
    draw.text((28, 18), "TRI-SHIELD  ·  DEMO DOCUMENT", font=_font(22, True), fill=(255, 255, 255))
    draw.text((28, 48), title, font=_font(28, True), fill=(255, 255, 255))
    draw.rectangle([0, size[1] - 54, size[0], size[1]], fill=(15, 23, 42))
    draw.text(
        (28, size[1] - 40),
        "FICTIONAL SAMPLE — NOT A GOVERNMENT ID — NO REAL PERSONAL DATA",
        font=_font(16),
        fill=(226, 232, 240),
    )
    draw.rectangle([24, 110, 240, 330], outline=accent, width=2)
    draw.rectangle([28, 114, 236, 326], fill=(248, 250, 252))
    draw.text((78, 200), "PHOTO", font=_font(22, True), fill=(148, 163, 184))
    return img, draw


def _write_fields(draw: ImageDraw.ImageDraw, lines: list[tuple[str, str]], x=280, y=130) -> None:
    for label, value in lines:
        draw.text((x, y), f"{label}:", font=_font(22, True), fill=(51, 65, 85))
        draw.text((x + 200, y), value, font=_font(22), fill=(15, 23, 42))
        y += 48


def _paste_qr(img: Image.Image, payload: dict) -> None:
    qr = _qr(payload)
    if qr is None:
        return
    qr = qr.resize((150, 150))
    x, y = img.size[0] - 196, 120
    mat = Image.new("RGB", (170, 170), (210, 214, 220))
    img.paste(mat, (x - 10, y - 10))
    img.paste(qr, (x, y))


def save_jpeg(img: Image.Image, path: Path, quality: int = 90) -> None:
    buf = BytesIO()
    img.convert("RGB").save(buf, format="JPEG", quality=quality, optimize=True)
    path.write_bytes(buf.getvalue())


def generate() -> dict[str, str]:
    OUT.mkdir(parents=True, exist_ok=True)
    aadhaar_no = make_valid_aadhaar("23451234567")
    clean_name = "PRIYA MEHTA"
    tampered_name = "RAJESH KUMAR"
    dob = "15/08/1994"
    pan_ok = "ABCPE1234F"
    pan_bad = "ABCXE1234F"

    # 1) Clean demo Aadhaar
    img, draw = _base("DEMO AADHAAR CARD (PLACEHOLDER)", (14, 116, 144))
    _write_fields(
        draw,
        [
            ("Name", clean_name),
            ("DOB", dob),
            ("Aadhaar No", aadhaar_no),
            ("Gender", "F"),
            ("VID", "DEMO-ONLY"),
        ],
    )
    _paste_qr(img, {"name": clean_name, "dob": dob, "id_number": aadhaar_no.replace(" ", ""), "type": "AADHAAR"})
    clean_path = OUT / "aadhaar_clean.jpg"
    save_jpeg(img, clean_path)

    # 2) Tampered: splice a *smooth* low-quality JPEG over name + photo.
    # Smooth fill keeps Canny low in the interior so ELA can see the splice.
    dirty = Image.open(clean_path).convert("RGB")

    patch = Image.new("RGB", (500, 92), (255, 80, 40))
    pd = ImageDraw.Draw(patch)
    pd.text((18, 28), tampered_name, font=_font(28, True), fill=(255, 255, 255))
    pbuf = BytesIO()
    patch.save(pbuf, format="JPEG", quality=1)
    pbuf.seek(0)
    dirty.paste(Image.open(pbuf).convert("RGB"), (260, 116))

    photo = Image.new("RGB", (200, 210), (36, 92, 48))
    pbuf = BytesIO()
    photo.save(pbuf, format="JPEG", quality=15)
    pbuf.seek(0)
    dirty.paste(Image.open(pbuf).convert("RGB"), (32, 118))

    tampered_path = OUT / "aadhaar_tampered.jpg"
    save_jpeg(dirty, tampered_path)

    # 3) Valid PAN
    img, draw = _base("DEMO PAN CARD (PLACEHOLDER)", (30, 64, 175))
    _write_fields(
        draw,
        [
            ("Name", "AMIT SHARMA"),
            ("DOB", "22/01/1990"),
            ("PAN No", pan_ok),
            ("Holder", "Individual (P)"),
        ],
    )
    _paste_qr(img, {"name": "AMIT SHARMA", "dob": "22/01/1990", "id_number": pan_ok, "type": "PAN"})
    pan_ok_path = OUT / "pan_valid.jpg"
    save_jpeg(img, pan_ok_path)

    # 4) Invalid PAN type code
    img, draw = _base("DEMO PAN CARD (PLACEHOLDER)", (127, 29, 29))
    _write_fields(
        draw,
        [
            ("Name", "NEHA VERMA"),
            ("DOB", "09/11/1988"),
            ("PAN No", pan_bad),
            ("Holder", "Type code X (invalid)"),
        ],
    )
    _paste_qr(img, {"name": "NEHA VERMA", "dob": "09/11/1988", "id_number": pan_bad, "type": "PAN"})
    pan_bad_path = OUT / "pan_invalid_type.jpg"
    save_jpeg(img, pan_bad_path)

    (OUT / "README.txt").write_text(
        "Synthetic demo cards only. Not UIDAI/ITD templates. No real identities.\n"
        f"Clean Aadhaar uses Verhoeff-valid number {aadhaar_no}.\n"
        f"Tampered Aadhaar has the name field digitally spliced to {tampered_name}.\n"
        f"Valid PAN {pan_ok} (4th char P). Invalid PAN {pan_bad} (4th char X).\n",
        encoding="utf-8",
    )
    return {
        "aadhaar_clean": str(clean_path),
        "aadhaar_tampered": str(tampered_path),
        "pan_valid": str(pan_ok_path),
        "pan_invalid_type": str(pan_bad_path),
        "aadhaar_no": aadhaar_no,
    }


if __name__ == "__main__":
    print(generate())
