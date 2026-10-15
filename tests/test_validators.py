import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.validators import (
    PANValidator,
    make_valid_aadhaar,
    verhoeff_checksum_ok,
)


def test_verhoeff_accepts_generated_aadhaar():
    number = make_valid_aadhaar("23451234567")
    assert verhoeff_checksum_ok(number)
    assert verhoeff_checksum_ok(number.replace(" ", ""))


def test_verhoeff_rejects_flipped_digit():
    number = make_valid_aadhaar("23451234567").replace(" ", "")
    flipped = number[:-1] + ("0" if number[-1] != "0" else "1")
    assert not verhoeff_checksum_ok(flipped)


def test_pan_valid_individual_type():
    result = PANValidator().validate("ABCPE1234F", "Amit Sharma", "22/01/1990")
    assert result.id_valid
    assert result.holder_type == "Individual"


def test_pan_invalid_type_code():
    result = PANValidator().validate("ABCXE1234F", "Neha Verma", "09/11/1988")
    assert not result.id_valid
    assert any(i.code == "pan_type" and not i.passed for i in result.issues)
    assert "Invalid type code" in " ".join(result.reasons)
