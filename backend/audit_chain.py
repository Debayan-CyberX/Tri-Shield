"""Hash-chained SQLite audit log (local tamper-evident ledger, SHA-256).

Privacy: document image bytes are NEVER stored. Only verification metadata
(document_type, score, verdict, timestamps, hashes) is persisted.
PERSIST_UPLOADED_DOCUMENTS stays False by design.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.config import AUDIT_DB_PATH, PERSIST_UPLOADED_DOCUMENTS
from backend.models import AuditRecord

GENESIS_HASH = "0" * 64


def _connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = Path(db_path or AUDIT_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    _init(conn)
    return conn


def _init(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS blocks (
            block_number INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            document_type TEXT NOT NULL,
            score REAL NOT NULL,
            result TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        )
        """
    )
    conn.commit()


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_hash(prev_hash: str, timestamp: str, document_type: str, score: float, result: str) -> str:
    body = {
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "document_type": document_type,
        "score": score,
        "result": result,
    }
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


def append_block(
    document_type: str,
    score: float,
    result: str,
    db_path: Optional[Path] = None,
) -> AuditRecord:
    if PERSIST_UPLOADED_DOCUMENTS:
        raise RuntimeError("Document persistence is disabled by privacy policy.")
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT block_number, hash FROM blocks ORDER BY block_number DESC LIMIT 1").fetchone()
        if row:
            block_number = int(row["block_number"]) + 1
            prev_hash = row["hash"]
        else:
            block_number = 1
            prev_hash = GENESIS_HASH
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        digest = compute_hash(prev_hash, timestamp, document_type, float(score), result)
        conn.execute(
            "INSERT INTO blocks (block_number, timestamp, document_type, score, result, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (block_number, timestamp, document_type, float(score), result, prev_hash, digest),
        )
        conn.commit()
        return AuditRecord(
            block_number=block_number,
            timestamp=timestamp,
            document_type=document_type,
            score=float(score),
            result=result,
            prev_hash=prev_hash,
            hash=digest,
            chain_valid=True,
        )
    finally:
        conn.close()


def list_blocks(limit: int = 50, db_path: Optional[Path] = None) -> list[AuditRecord]:
    conn = _connect(db_path)
    try:
        validity = verify_chain(db_path=db_path, conn=conn)
        rows = conn.execute(
            "SELECT * FROM blocks ORDER BY block_number DESC LIMIT ?",
            (limit,),
        ).fetchall()
        broken = validity["broken_from"]
        records = []
        for row in rows:
            n = int(row["block_number"])
            records.append(
                AuditRecord(
                    block_number=n,
                    timestamp=row["timestamp"],
                    document_type=row["document_type"],
                    score=float(row["score"]),
                    result=row["result"],
                    prev_hash=row["prev_hash"],
                    hash=row["hash"],
                    chain_valid=broken is None or n < broken,
                )
            )
        return records
    finally:
        conn.close()


def verify_chain(db_path: Optional[Path] = None, conn: Optional[sqlite3.Connection] = None) -> dict:
    own = conn is None
    conn = conn or _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM blocks ORDER BY block_number ASC").fetchall()
        prev = GENESIS_HASH
        expected_n = 1
        for row in rows:
            n = int(row["block_number"])
            if n != expected_n or row["prev_hash"] != prev:
                return {"intact": False, "broken_from": n, "reason": "Block linking / numbering mismatch."}
            expected = compute_hash(
                row["prev_hash"],
                row["timestamp"],
                row["document_type"],
                float(row["score"]),
                row["result"],
            )
            if expected != row["hash"]:
                return {"intact": False, "broken_from": n, "reason": "SHA-256 mismatch — record contents were altered."}
            prev = row["hash"]
            expected_n += 1
        return {"intact": True, "broken_from": None, "reason": "Chain verified."}
    finally:
        if own:
            conn.close()


def simulate_tamper(block_number: int = 1, db_path: Optional[Path] = None) -> dict:
    """Demo helper: mutate a stored score without updating the hash (breaks the chain)."""
    conn = _connect(db_path)
    try:
        conn.execute("UPDATE blocks SET score = score - 1 WHERE block_number = ?", (block_number,))
        conn.commit()
        return verify_chain(conn=conn)
    finally:
        conn.close()
