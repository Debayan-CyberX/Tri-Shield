"""FastAPI backend — /verify and audit-chain endpoints. Fully offline."""

from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from backend.audit_chain import list_blocks, simulate_tamper, verify_chain
from backend.config import PERSIST_UPLOADED_DOCUMENTS
from backend.models import AuditLogResponse, HealthResponse, VerifyResponse
from backend.pipeline import verify_bytes

app = FastAPI(
    title="Tri-Shield",
    description="Offline AI document verification — DATA + IMAGE + PROOF fusion.",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        offline_mode=True,
        persist_documents=PERSIST_UPLOADED_DOCUMENTS,
    )


@app.post("/verify", response_model=VerifyResponse)
async def verify(file: UploadFile = File(...)) -> VerifyResponse:
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty upload.")
    try:
        return verify_bytes(data, file.filename or "upload.bin")
    except Exception as exc:
        raise HTTPException(400, f"Verification failed: {exc}") from exc


@app.get("/audit", response_model=AuditLogResponse)
def audit(limit: int = 50) -> AuditLogResponse:
    records = list_blocks(limit=limit)
    chain = verify_chain()
    return AuditLogResponse(chain_intact=bool(chain["intact"]), records=records)


@app.post("/audit/verify")
def audit_verify() -> dict:
    return verify_chain()


@app.post("/audit/simulate-tamper")
def audit_simulate(block_number: int = 1) -> dict:
    """Demo-only: alter a stored score without recomputing the hash."""
    return simulate_tamper(block_number=block_number)
