"""Runtime configuration. Verification path is fully offline — no identity APIs."""

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Privacy promise: uploaded document bytes are processed in-memory and discarded.
# Only verification metadata (type, score, verdict, hashes) is written to SQLite.
PERSIST_UPLOADED_DOCUMENTS = False

AUDIT_DB_PATH = DATA_DIR / "audit_chain.db"

PASS_THRESHOLD = 80
# Localized ELA anomaly covering >= 1% of the page is treated as forgery.
TAMPER_AREA_FAIL_PCT = 1.0

ELA_JPEG_QUALITY = 90
ELA_SCALE = 20
ELA_PIXEL_THRESHOLD = 8
ELA_LOCAL_DELTA = 9

TESSERACT_CMD_CANDIDATES = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    "tesseract",
]
