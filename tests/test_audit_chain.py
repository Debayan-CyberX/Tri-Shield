import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.audit_chain import append_block, list_blocks, simulate_tamper, verify_chain


def test_hash_chain_appends_and_verifies(tmp_path):
    db = tmp_path / "audit.db"
    a = append_block("AADHAAR", 96.0, "PASS", db_path=db)
    b = append_block("PAN", 93.0, "PASS", db_path=db)
    assert a.block_number == 1
    assert b.prev_hash == a.hash
    assert verify_chain(db_path=db)["intact"] is True
    rows = list_blocks(db_path=db)
    assert rows[0].block_number == 2


def test_tampering_stored_score_breaks_chain(tmp_path):
    db = tmp_path / "audit.db"
    append_block("AADHAAR", 96.0, "PASS", db_path=db)
    append_block("PAN", 11.0, "FAIL", db_path=db)
    broken = simulate_tamper(1, db_path=db)
    assert broken["intact"] is False
    assert broken["broken_from"] == 1
    flagged = list_blocks(db_path=db)
    assert any(r.chain_valid is False for r in flagged)
