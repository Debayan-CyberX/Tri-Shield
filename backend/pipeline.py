"""End-to-end 5-stage verification pipeline."""

from __future__ import annotations

import base64
import io
import time

from backend.audit_chain import append_block
from backend.forensics import analyze_image
from backend.ingestion import load_document
from backend.models import ForensicSummary, VerifyResponse
from backend.ocr import extract_fields
from backend.scoring import fuse
from backend.validators import validate_document


def image_to_b64_png(image) -> str:
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def verify_bytes(data: bytes, filename: str = "upload.bin") -> VerifyResponse:
    t0 = time.perf_counter()
    image = load_document(data, filename)
    extracted = extract_fields(image)
    validation = validate_document(extracted.document_type, extracted.id_number, extracted.name, extracted.dob)
    forensics = analyze_image(image)
    scored = fuse(extracted, validation, forensics)
    audit = append_block(extracted.document_type, scored.score, scored.verdict)
    ms = (time.perf_counter() - t0) * 1000.0

    return VerifyResponse(
        score=scored.score,
        verdict=scored.verdict,
        verified_authentic=scored.verified_authentic,
        audit_proof_ready=True,
        document_type=extracted.document_type,
        extracted=extracted,
        checks=scored.checks,
        reasons=scored.reasons,
        forensics=ForensicSummary(
            ela_status=forensics.ela_status,
            tamper_area_pct=forensics.tamper_area_pct,
            peak_error=forensics.peak_error,
            suspicious_regions=forensics.suspicious_regions,
            needs_review=forensics.needs_review,
            heatmap_png_b64=image_to_b64_png(forensics.heatmap),
        ),
        audit=audit,
        processing_ms=round(ms, 1),
        extra={
            "privacy": "Uploaded document bytes are not persisted; audit log stores metadata + hashes only.",
            "offline": True,
        },
    )
