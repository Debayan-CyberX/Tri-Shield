"""Stage 1 — document ingestion and normalization (images + PDF pages)."""

from __future__ import annotations

import io

import cv2
import numpy as np
from PIL import Image, ImageOps

try:
    import fitz  # PyMuPDF
except ImportError:  # pragma: no cover
    fitz = None


MAX_SIDE = 1600


def load_document(data: bytes, filename: str = "upload.bin") -> Image.Image:
    name = (filename or "").lower()
    if name.endswith(".pdf") or data[:4] == b"%PDF":
        return _pdf_first_page(data)
    image = Image.open(io.BytesIO(data))
    image = ImageOps.exif_transpose(image)
    return _normalize(image.convert("RGB"))


def _pdf_first_page(data: bytes) -> Image.Image:
    if fitz is None:
        raise RuntimeError("PyMuPDF is required to ingest PDF documents.")
    doc = fitz.open(stream=data, filetype="pdf")
    if doc.page_count < 1:
        raise ValueError("PDF has no pages.")
    page = doc.load_page(0)
    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
    image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
    doc.close()
    return _normalize(image)


def _normalize(image: Image.Image) -> Image.Image:
    w, h = image.size
    scale = min(1.0, MAX_SIDE / max(w, h))
    if scale < 1.0:
        image = image.resize((int(w * scale), int(h * scale)), Image.Resampling.LANCZOS)
    return image


def pil_to_bgr(image: Image.Image) -> np.ndarray:
    rgb = np.array(image.convert("RGB"))
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)


def enhance_for_ocr(image: Image.Image) -> Image.Image:
    """Deskew + denoise + contrast stretch for Tesseract."""
    bgr = pil_to_bgr(image)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    gray = cv2.fastNlMeansDenoising(gray, h=12)
    gray = _deskew(gray)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    gray = clahe.apply(gray)
    return Image.fromarray(gray)


def _deskew(gray: np.ndarray) -> np.ndarray:
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    coords = np.column_stack(np.where(thresh > 0))
    if coords.size < 50:
        return gray
    angle = cv2.minAreaRect(coords)[-1]
    if angle < -45:
        angle = -(90 + angle)
    else:
        angle = -angle
    if abs(angle) < 0.4 or abs(angle) > 20:
        return gray
    h, w = gray.shape
    matrix = cv2.getRotationMatrix2D((w // 2, h // 2), angle, 1.0)
    return cv2.warpAffine(gray, matrix, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
