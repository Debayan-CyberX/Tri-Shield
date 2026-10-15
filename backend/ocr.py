"""Stage 2 — OCR extraction (Tesseract primary, EasyOCR optional fallback)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from PIL import Image

from backend.ingestion import enhance_for_ocr
from backend.models import ExtractedFields
from backend.validators import AADHAAR_RE, DOB_RE, NAME_RE, PAN_FIND_RE, detect_document_type

try:
    import pytesseract
except ImportError:  # pragma: no cover
    pytesseract = None


def _configure_tesseract() -> bool:
    if pytesseract is None:
        return False
    from backend.config import TESSERACT_CMD_CANDIDATES

    env = os.environ.get("TESSERACT_CMD")
    candidates = [env] if env else []
    candidates.extend(TESSERACT_CMD_CANDIDATES)
    for cmd in candidates:
        if not cmd:
            continue
        if cmd == "tesseract" or Path(cmd).exists():
            pytesseract.pytesseract.tesseract_cmd = cmd
            try:
                pytesseract.get_tesseract_version()
                return True
            except Exception:
                continue
    return False


_TESSERACT_READY: Optional[bool] = None


def tesseract_available() -> bool:
    global _TESSERACT_READY
    if _TESSERACT_READY is None:
        _TESSERACT_READY = _configure_tesseract()
    return _TESSERACT_READY


def extract_fields(image: Image.Image) -> ExtractedFields:
    raw, engine = _ocr_text(image)
    raw = (raw or "").replace("\x0c", " ").strip()
    name = _first(NAME_RE, raw)
    dob = _first(DOB_RE, raw)
    aadhaar = _first(AADHAAR_RE, raw)
    pan = _first(PAN_FIND_RE, raw.upper() if raw else "")

    id_number = None
    if aadhaar:
        id_number = re.sub(r"\s+", " ", aadhaar).strip()
    elif pan:
        id_number = pan.upper()

    # OpenCV QR payload (demo cards embed structured JSON for OCR-hostile photos).
    qr_fields = _qr_payload(image)
    if qr_fields:
        name = name or qr_fields.get("name")
        dob = dob or qr_fields.get("dob")
        id_number = id_number or qr_fields.get("id_number")
        raw = (raw + "\n" + qr_fields.get("raw", "")).strip()

    doc_type = detect_document_type(raw, id_number)
    ocr_ok = bool(raw.strip()) or bool(id_number)
    return ExtractedFields(
        document_type=doc_type,
        name=name.strip().title() if name else None,
        dob=dob,
        id_number=id_number,
        raw_text=raw[:4000],
        ocr_engine=engine,
        ocr_ok=ocr_ok,
    )


def _ocr_text(image: Image.Image) -> tuple[str, str]:
    prepared = enhance_for_ocr(image)
    if tesseract_available():
        try:
            text = pytesseract.image_to_string(prepared, config="--psm 6")
            if text.strip():
                return text, "tesseract"
        except Exception:
            pass
    easy = _easyocr_text(image)
    if easy:
        return easy, "easyocr"
    return "", "none"


def _easyocr_text(image: Image.Image) -> str:
    try:
        import easyocr
        import numpy as np
    except ImportError:
        return ""
    try:
        reader = easyocr.Reader(["en"], gpu=False, verbose=False)
        lines = reader.readtext(np.array(image.convert("RGB")), detail=0)
        return "\n".join(str(x) for x in lines)
    except Exception:
        return ""


def _qr_payload(image: Image.Image) -> dict:
    try:
        import cv2
        import json
        import numpy as np
    except ImportError:
        return {}
    bgr = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(bgr)
    if not data:
        return {}
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            parsed["raw"] = data
            return parsed
    except json.JSONDecodeError:
        return {"raw": data}
    return {}


def _first(pattern: re.Pattern, text: str) -> Optional[str]:
    if not text:
        return None
    m = pattern.search(text)
    return m.group(1).strip() if m else None
