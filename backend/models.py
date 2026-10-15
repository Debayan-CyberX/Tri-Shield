"""Pydantic schemas for the FastAPI verification API."""

from typing import Any, Optional

from pydantic import BaseModel, Field


class ExtractedFields(BaseModel):
    document_type: str = "UNKNOWN"
    name: Optional[str] = None
    dob: Optional[str] = None
    id_number: Optional[str] = None
    raw_text: str = ""
    ocr_engine: str = "none"
    ocr_ok: bool = False


class CheckResult(BaseModel):
    name: str
    passed: bool
    detail: str
    status_label: str


class ForensicSummary(BaseModel):
    ela_status: str
    tamper_area_pct: float
    peak_error: float
    suspicious_regions: int
    needs_review: bool
    heatmap_png_b64: Optional[str] = None


class AuditRecord(BaseModel):
    block_number: int
    timestamp: str
    document_type: str
    score: float
    result: str
    prev_hash: str
    hash: str
    chain_valid: bool = True


class VerifyResponse(BaseModel):
    score: float
    verdict: str
    verified_authentic: bool
    audit_proof_ready: bool
    document_type: str
    extracted: ExtractedFields
    checks: list[CheckResult]
    reasons: list[str]
    forensics: ForensicSummary
    audit: AuditRecord
    processing_ms: float
    extra: dict[str, Any] = Field(default_factory=dict)


class AuditLogResponse(BaseModel):
    chain_intact: bool
    records: list[AuditRecord]


class HealthResponse(BaseModel):
    status: str
    offline_mode: bool = True
    persist_documents: bool = False
