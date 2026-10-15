"""Stage 4 — Error Level Analysis (Krawetz) + OpenCV anomalous-region detection."""

from __future__ import annotations

import io
from dataclasses import dataclass

import cv2
import numpy as np
from PIL import Image

from backend.config import (
    ELA_JPEG_QUALITY,
    ELA_LOCAL_DELTA,
    ELA_PIXEL_THRESHOLD,
    ELA_SCALE,
    TAMPER_AREA_FAIL_PCT,
)


@dataclass
class ForensicResult:
    ela_status: str  # CLEAN | TAMPERED | NEEDS_REVIEW
    tamper_area_pct: float
    peak_error: float
    mean_error: float
    suspicious_regions: int
    needs_review: bool
    heatmap: Image.Image
    mask: np.ndarray


def analyze_image(image: Image.Image) -> ForensicResult:
    rgb = image.convert("RGB")
    ela = error_level_map(rgb, quality=ELA_JPEG_QUALITY, scale=ELA_SCALE)
    gray = cv2.cvtColor(np.array(ela), cv2.COLOR_RGB2GRAY)

    # Localized ELA contrast: flag tiles hotter than their neighborhood median.
    # Uniform headers/backgrounds cancel out; spliced patches do not.
    mask = _local_contrast_mask(gray, block=16, delta=ELA_LOCAL_DELTA)
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel)

    total = max(mask.size, 1)
    min_area = max(200, int(0.003 * total))
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    regions = [c for c in contours if cv2.contourArea(c) >= min_area]
    h_img, w_img = mask.shape
    filtered = []
    for contour in regions:
        x, y, bw, bh = cv2.boundingRect(contour)
        if bw >= 0.62 * w_img:
            continue  # header/footer chrome
        if y <= int(0.14 * h_img) and bw >= 0.45 * w_img:
            continue
        filtered.append(contour)
    regions = filtered
    kept = np.zeros_like(mask)
    for contour in regions:
        cv2.drawContours(kept, [contour], -1, 255, thickness=-1)
    mask = kept

    tamper_pct = float(np.count_nonzero(mask)) * 100.0 / total
    peak = float(gray.max())
    mean = float(gray.mean())
    heatmap = build_heatmap(rgb, ela, mask, regions)

    if tamper_pct >= TAMPER_AREA_FAIL_PCT:
        status = "TAMPERED"
        needs_review = False
    elif tamper_pct > 0.2 or len(regions) > 0:
        status = "NEEDS_REVIEW"
        needs_review = True
    else:
        status = "CLEAN"
        needs_review = False

    return ForensicResult(
        ela_status=status,
        tamper_area_pct=round(tamper_pct, 3),
        peak_error=round(peak, 2),
        mean_error=round(mean, 2),
        suspicious_regions=len(regions),
        needs_review=needs_review,
        heatmap=heatmap,
        mask=mask,
    )


def _local_contrast_mask(ela_gray: np.ndarray, block: int = 16, delta: float = 7.0) -> np.ndarray:
    h, w = ela_gray.shape
    gh, gw = h // block, w // block
    if gh < 3 or gw < 3:
        return (ela_gray >= ELA_PIXEL_THRESHOLD).astype(np.uint8) * 255
    grid = np.zeros((gh, gw), np.float32)
    for i in range(gh):
        for j in range(gw):
            grid[i, j] = float(ela_gray[i * block : (i + 1) * block, j * block : (j + 1) * block].mean())
    grid_u8 = np.clip(grid, 0, 255).astype(np.uint8)
    local_med = cv2.medianBlur(grid_u8, 5).astype(np.float32)
    mask = np.zeros_like(ela_gray)
    for i in range(gh):
        for j in range(gw):
            if grid[i, j] >= local_med[i, j] + delta and grid[i, j] >= ELA_PIXEL_THRESHOLD:
                mask[i * block : (i + 1) * block, j * block : (j + 1) * block] = 255
    return mask


def error_level_map(image: Image.Image, quality: int = 90, scale: int = 15) -> Image.Image:
    """Neal Krawetz ELA: residual after JPEG recompression, scaled for display."""
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    recompressed = Image.open(buf).convert("RGB")
    orig = np.asarray(image, dtype=np.float32)
    rec = np.asarray(recompressed, dtype=np.float32)
    diff = np.abs(orig - rec) * scale
    return Image.fromarray(np.clip(diff, 0, 255).astype(np.uint8))


def build_heatmap(
    original: Image.Image,
    ela: Image.Image,
    mask: np.ndarray,
    regions: list,
) -> Image.Image:
    base = np.array(original.convert("RGB"))
    ela_gray = cv2.cvtColor(np.array(ela), cv2.COLOR_RGB2GRAY)
    color = cv2.applyColorMap(ela_gray, cv2.COLORMAP_JET)
    color = cv2.cvtColor(color, cv2.COLOR_BGR2RGB)
    overlay = cv2.addWeighted(base, 0.55, color, 0.45, 0)

    highlight = overlay.copy()
    highlight[mask > 0] = (0.35 * highlight[mask > 0] + 0.65 * np.array([220, 30, 30])).astype(np.uint8)
    overlay = np.where(mask[..., None] > 0, highlight, overlay)

    for contour in regions:
        x, y, w, h = cv2.boundingRect(contour)
        cv2.rectangle(overlay, (x, y), (x + w, y + h), (255, 20, 20), 3)
        cv2.putText(overlay, "TAMPER", (x, max(18, y - 6)), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 20, 20), 2)

    return Image.fromarray(overlay)
