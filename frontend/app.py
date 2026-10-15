"""Streamlit UI — Document Verification & Integrity Check."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import requests
import streamlit as st
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.audit_chain import list_blocks, simulate_tamper, verify_chain
from backend.pipeline import verify_bytes

API = "http://127.0.0.1:8000"
SAMPLES = ROOT / "sample_docs"

st.set_page_config(page_title="Tri-Shield | Document Verification", layout="wide", page_icon="🛡️")

st.markdown(
    """
    <style>
      .stApp { background: linear-gradient(180deg, #070b14 0%, #0f172a 100%); color: #e2e8f0; }
      h1, h2, h3 { color: #f8fafc !important; }
      .badge-offline { display:inline-flex; gap:8px; align-items:center; background:#052e16;
        color:#86efac; border:1px solid #16a34a; padding:6px 12px; border-radius:999px; font-weight:600; }
      .dot { width:8px; height:8px; background:#22c55e; border-radius:50%; display:inline-block; }
      .score-pass { font-size: 2.4rem; font-weight: 800; color: #4ade80; }
      .score-fail { font-size: 2.4rem; font-weight: 800; color: #f87171; }
      .panel { background:#111827; border:1px solid #1f2937; border-radius:16px; padding:1rem 1.2rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def _verify_upload(data: bytes, name: str):
    try:
        res = requests.post(f"{API}/verify", files={"file": (name, data)}, timeout=3)
        if res.ok:
            return res.json(), "api"
    except Exception:
        pass
    model = verify_bytes(data, name)
    return model.model_dump(), "local"


def _audit_rows():
    try:
        res = requests.get(f"{API}/audit", timeout=2)
        if res.ok:
            body = res.json()
            return body.get("records", []), body.get("chain_intact", True), "api"
    except Exception:
        pass
    chain = verify_chain()
    return [r.model_dump() for r in list_blocks(40)], bool(chain["intact"]), "local"


header_l, header_r = st.columns([3, 1])
with header_l:
    st.title("Tri-Shield")
    st.caption("Document Verification & Integrity Check  ·  SIH26188  ·  Cyber Sentinels")
with header_r:
    st.markdown(
        '<div style="text-align:right;margin-top:1.4rem">'
        '<span class="badge-offline"><span class="dot"></span> Offline Mode</span></div>',
        unsafe_allow_html=True,
    )

left, right = st.columns([1.05, 1.2], gap="large")

with left:
    st.subheader("Upload document")
    uploaded = st.file_uploader("Drag & drop Aadhaar / PAN / ID (JPG, PNG, PDF)", type=["jpg", "jpeg", "png", "pdf"])
    st.markdown("**Demo samples**")
    sample_choice = st.selectbox(
        "Load a synthetic sample",
        [
            "(none)",
            "aadhaar_clean.jpg",
            "aadhaar_tampered.jpg",
            "pan_valid.jpg",
            "pan_invalid_type.jpg",
        ],
    )
    file_bytes, file_name, preview = None, None, None
    if uploaded is not None:
        file_bytes = uploaded.getvalue()
        file_name = uploaded.name
        if not file_name.lower().endswith(".pdf"):
            preview = Image.open(uploaded).convert("RGB")
    elif sample_choice != "(none)":
        path = SAMPLES / sample_choice
        if path.exists():
            file_bytes = path.read_bytes()
            file_name = path.name
            preview = Image.open(path).convert("RGB")
        else:
            st.warning("Sample images not generated yet. Run: `python sample_docs/generate.py`")

    if preview is not None:
        st.image(preview, caption=file_name, use_container_width=True)
    elif file_name:
        st.info(f"Loaded {file_name} (PDF — preview after verification heatmap).")

    run = st.button("Run Tri-Shield verification", type="primary", disabled=file_bytes is None, use_container_width=True)

with right:
    st.subheader("Verification Result")
    if run and file_bytes:
        with st.spinner("Running DATA → IMAGE → PROOF pipeline…"):
            result, source = _verify_upload(file_bytes, file_name or "upload.bin")
        st.session_state["last_result"] = result
        st.session_state["source"] = source

    result = st.session_state.get("last_result")
    if not result:
        st.info("Upload a document or pick a demo sample, then run verification.")
    else:
        score = result["score"]
        verdict = result["verdict"]
        cls = "score-pass" if verdict == "PASS" else "score-fail"
        mark = "✓ PASS" if verdict == "PASS" else "✗ FAIL"
        st.markdown(f'<div class="{cls}">Score: {score:.0f}% {mark}</div>', unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)
        c1.metric("Verified / Authentic", "YES" if result["verified_authentic"] else "NO")
        c2.metric("Audit Proof Ready", "YES" if result["audit_proof_ready"] else "NO")
        c3.metric("Latency", f"{result.get('processing_ms', 0):.0f} ms")

        st.markdown("**Checklist**")
        for check in result.get("checks", []):
            icon = "✅" if check["passed"] else "❌"
            st.write(f"{icon} **{check['name']}** → {check['status_label']}  \n{check['detail']}")

        heat_b64 = (result.get("forensics") or {}).get("heatmap_png_b64")
        if heat_b64:
            st.markdown("**ELA tamper heatmap**")
            st.image(base64.b64decode(heat_b64), caption="Suspicious regions boxed in red", use_container_width=True)

        st.markdown("**Why this verdict**")
        for reason in result.get("reasons", []):
            st.write(f"- {reason}")

        audit = result.get("audit") or {}
        digest = audit.get("hash", "")
        st.code(
            f"Block #{audit.get('block_number')}  ·  {digest[:16]}…{digest[-8:] if digest else ''}",
            language=None,
        )
        st.caption(f"Pipeline source: {st.session_state.get('source', 'local')}  ·  documents are not stored")

st.markdown("---")
st.subheader("Blockchain Verification Log")
log_cols = st.columns([3, 1, 1])
with log_cols[1]:
    if st.button("Re-verify chain"):
        st.session_state["force_refresh"] = True
with log_cols[2]:
    if st.button("Simulate ledger tamper"):
        try:
            requests.post(f"{API}/audit/simulate-tamper", params={"block_number": 1}, timeout=2)
        except Exception:
            simulate_tamper(1)
        st.session_state["force_refresh"] = True

records, intact, _src = _audit_rows()
if intact:
    st.success("Hash chain intact — historical records have not been altered.")
else:
    st.error("FORGED / BROKEN CHAIN — a stored block no longer matches its SHA-256 hash.")

if records:
    rows = []
    for rec in records:
        digest = rec.get("hash", "")
        flag = "" if rec.get("chain_valid", True) else " ⚠ BROKEN"
        rows.append(
            {
                "#": rec.get("block_number"),
                "Time": rec.get("timestamp"),
                "Score": rec.get("score"),
                "Result": rec.get("result") + flag,
                "Hash": (digest[:12] + "…" + digest[-6:]) if digest else "",
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    st.caption("No verifications yet. Run the demo samples to grow the chain.")
