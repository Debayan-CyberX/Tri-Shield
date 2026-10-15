# Tri-Shield

Offline **three-layer** document verification prototype for Smart India Hackathon 2026  
Problem statement **SIH26188** (Blockchain & Cybersecurity) · Team **Cyber Sentinels**

Tri-Shield fuses:

1. **DATA** — Verhoeff (Aadhaar) + PAN regex / holder-type checks  
2. **IMAGE** — Error Level Analysis (Krawetz) + OpenCV anomalous-region boxes  
3. **PROOF** — SHA-256 hash-chained SQLite audit log (local tamper-evident ledger)

There are **no identity-API calls** on the verification path. Uploaded images are processed in memory and **not stored**; the ledger keeps only metadata + hashes.

Policy: localized ELA tamper covering **≥ 1%** of the page is treated as **FAIL** (forged), even if checksums pass.

## Setup

Python 3.11+ recommended. Tesseract OCR is optional but improves extraction on arbitrary photos (demo cards also embed a QR payload so the flow still works without Tesseract).

```powershell
cd C:\Users\shivl\Projects\tri-shield
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python sample_docs/generate.py
```

Install Tesseract if you want full OCR on camera photos: [UB Mannheim Tesseract](https://github.com/UB-Mannheim/tesseract/wiki). Then set:

```powershell
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
```

## Run

Terminal 1 — API:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Terminal 2 — UI (works even if the API is down; it falls back to an in-process pipeline):

```powershell
.\.venv\Scripts\Activate.ps1
python -m streamlit run frontend/app.py
```

Open the Streamlit URL, pick a demo sample, click **Run Tri-Shield verification**.

## 30-second demo

| Sample | Expected |
|---|---|
| `sample_docs/aadhaar_clean.jpg` | ~96% PASS, Verhoeff match, ELA clean |
| `sample_docs/aadhaar_tampered.jpg` | ~18% FAIL, name region boxed red on heatmap |
| `sample_docs/pan_valid.jpg` | ~93% PASS, regex + type code P |
| `sample_docs/pan_invalid_type.jpg` | ~11% FAIL, **Invalid type code 'X'** |
| **Simulate ledger tamper** | Red **FORGED / BROKEN CHAIN** on the log |

Samples are **fictional placeholder cards**, not UIDAI/ITD templates and not real people.

## Tests

```powershell
python -m pytest -q
```

## API

- `GET /health`
- `POST /verify` (multipart `file`)
- `GET /audit`
- `POST /audit/verify`
- `POST /audit/simulate-tamper?block_number=1`

## Layout

```
tri-shield/
├── backend/          FastAPI + 5-stage pipeline
├── frontend/         Streamlit UI
├── sample_docs/      Synthetic demo cards
├── tests/
└── data/             SQLite audit chain (created at runtime)
```

Adding Voter ID / Passport / DL later: implement another `DocumentValidator` in `backend/validators.py` and register it in `VALIDATORS`. Optional CCTNS-style APIs belong in `backend/gov_hooks.py` (not invoked offline). Optional CNN scoring lives in `backend/ml_optional.py` and must remain an extra signal, not a replacement for checksums + ELA.
