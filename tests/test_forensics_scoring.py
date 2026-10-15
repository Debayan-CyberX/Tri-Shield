import sys
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import TAMPER_AREA_FAIL_PCT
from backend.forensics import analyze_image
from backend.models import ExtractedFields
from backend.scoring import fuse
from backend.validators import AadhaarValidator, PANValidator, make_valid_aadhaar


def _card(text: str) -> Image.Image:
    img = Image.new("RGB", (640, 400), (240, 240, 240))
    d = ImageDraw.Draw(img)
    d.text((40, 40), text, fill=(10, 10, 10))
    return img


def test_ela_flags_spliced_patch():
    clean = _card("Name: PRIYA MEHTA")
    buf = BytesIO()
    clean.save(buf, format="JPEG", quality=90)
    buf.seek(0)
    jpeg = Image.open(buf).convert("RGB")
    patch = Image.new("RGB", (280, 90), (20, 180, 40))
    pbuf = BytesIO()
    patch.save(pbuf, format="JPEG", quality=12)
    pbuf.seek(0)
    jpeg.paste(Image.open(pbuf).convert("RGB"), (40, 120))
    result = analyze_image(jpeg)
    assert result.tamper_area_pct >= TAMPER_AREA_FAIL_PCT or result.suspicious_regions >= 1


def test_clean_structured_pan_scores_high_without_tamper():
    extracted = ExtractedFields(
        document_type="PAN",
        name="Amit Sharma",
        dob="22/01/1990",
        id_number="ABCPE1234F",
        raw_text="PAN Name: Amit Sharma",
        ocr_engine="test",
        ocr_ok=True,
    )
    validation = PANValidator().validate(extracted.id_number, extracted.name, extracted.dob)
    forensics = analyze_image(_card("PAN ABCPE1234F Amit Sharma"))
    # Force clean forensics for this unit (generated JPEG-from-PNG can be noisy).
    forensics.ela_status = "CLEAN"
    forensics.tamper_area_pct = 0.0
    forensics.needs_review = False
    scored = fuse(extracted, validation, forensics)
    assert scored.verdict == "PASS"
    assert scored.score >= 93


def test_invalid_pan_type_scores_near_demo_fail():
    extracted = ExtractedFields(
        document_type="PAN",
        name="Neha Verma",
        dob="09/11/1988",
        id_number="ABCXE1234F",
        raw_text="PAN",
        ocr_engine="test",
        ocr_ok=True,
    )
    validation = PANValidator().validate(extracted.id_number, extracted.name, extracted.dob)
    forensics = analyze_image(_card("PAN ABCXE1234F"))
    forensics.ela_status = "CLEAN"
    forensics.tamper_area_pct = 0.0
    forensics.needs_review = False
    scored = fuse(extracted, validation, forensics)
    assert scored.verdict == "FAIL"
    assert scored.score <= 11


def test_tamper_one_percent_fails_even_if_checksum_ok():
    from types import SimpleNamespace

    extracted = ExtractedFields(
        document_type="AADHAAR",
        name="Priya Mehta",
        dob="15/08/1994",
        id_number=make_valid_aadhaar("23451234567"),
        ocr_engine="test",
        ocr_ok=True,
    )
    validation = AadhaarValidator().validate(extracted.id_number, extracted.name, extracted.dob)
    forensics = SimpleNamespace(
        ela_status="TAMPERED",
        tamper_area_pct=1.0,
        peak_error=120,
        suspicious_regions=1,
        needs_review=False,
    )
    scored = fuse(extracted, validation, forensics)
    assert scored.verdict == "FAIL"
    assert scored.score <= 18
