"""Stage 3 — modular structural validators (Aadhaar Verhoeff, PAN regex/type)."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Verhoeff tables (Aadhaar checksum; dihedral group D5).
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
PAN_TYPE_CODES = {
    "P": "Individual",
    "C": "Company",
    "H": "HUF (Hindu Undivided Family)",
    "F": "Firm",
    "A": "Association of Persons",
    "T": "Trust",
    "B": "Body of Individuals",
    "L": "Local Authority",
    "J": "Artificial Juridical Person",
    "G": "Government",
}

AADHAAR_RE = re.compile(r"\b(\d{4}\s?\d{4}\s?\d{4})\b")
PAN_FIND_RE = re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b")
DOB_RE = re.compile(
    r"(?:DOB|Date of Birth|D\.?O\.?B\.?)[:\s]*([0-9]{2}[/-][0-9]{2}[/-][0-9]{4})",
    re.IGNORECASE,
)
NAME_RE = re.compile(r"(?:Name|Holder)[:\s]+([A-Z][A-Za-z.' ]{1,60})", re.IGNORECASE)


def verhoeff_checksum_ok(number: str) -> bool:
    digits = re.sub(r"\D", "", number or "")
    if len(digits) != 12:
        return False
    checksum = 0
    for i, ch in enumerate(reversed(digits)):
        checksum = _D[checksum][_P[i % 8][int(ch)]]
    return checksum == 0


def verhoeff_check_digit(eleven_digits: str) -> str:
    digits = re.sub(r"\D", "", eleven_digits)
    if len(digits) != 11:
        raise ValueError("Need 11 digits to compute Verhoeff check digit.")
    checksum = 0
    for i, ch in enumerate(reversed(digits + "0")):
        checksum = _D[checksum][_P[i % 8][int(ch)]]
    return str(_INV[checksum])


def make_valid_aadhaar(eleven_digits: str) -> str:
    d = re.sub(r"\D", "", eleven_digits)
    if len(d) != 11:
        raise ValueError("Need 11 digits.")
    full = d + verhoeff_check_digit(d)
    return f"{full[:4]} {full[4:8]} {full[8:]}"


@dataclass
class ValidationIssue:
    code: str
    message: str
    passed: bool


@dataclass
class ValidationResult:
    document_type: str
    id_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    holder_type: Optional[str] = None

    @property
    def reasons(self) -> list[str]:
        return [i.message for i in self.issues if not i.passed]


class DocumentValidator(ABC):
    document_type: str = "GENERIC"

    @abstractmethod
    def validate(self, id_number: Optional[str], name: Optional[str], dob: Optional[str]) -> ValidationResult:
        ...


class AadhaarValidator(DocumentValidator):
    document_type = "AADHAAR"

    def validate(self, id_number: Optional[str], name: Optional[str], dob: Optional[str]) -> ValidationResult:
        issues: list[ValidationIssue] = []
        digits = re.sub(r"\D", "", id_number or "")
        if len(digits) != 12:
            issues.append(ValidationIssue("aadhaar_length", "Aadhaar must be 12 digits.", False))
        elif digits[0] in "01":
            issues.append(ValidationIssue("aadhaar_prefix", "Aadhaar cannot start with 0 or 1.", False))
        if digits and not verhoeff_checksum_ok(digits):
            issues.append(
                ValidationIssue("verhoeff", "Verhoeff checksum mismatch — ID number is not structurally valid.", False)
            )
        elif len(digits) == 12:
            issues.append(ValidationIssue("verhoeff", "Verhoeff checksum matched.", True))
        issues.extend(_common_field_checks(name, dob, required_id=bool(digits)))
        id_valid = all(i.passed for i in issues if i.code in {"aadhaar_length", "aadhaar_prefix", "verhoeff"})
        return ValidationResult("AADHAAR", id_valid, issues)


class PANValidator(DocumentValidator):
    document_type = "PAN"

    def validate(self, id_number: Optional[str], name: Optional[str], dob: Optional[str]) -> ValidationResult:
        issues: list[ValidationIssue] = []
        pan = re.sub(r"\s", "", (id_number or "")).upper()
        holder_type = None
        if not PAN_REGEX.match(pan):
            issues.append(
                ValidationIssue("pan_regex", "PAN must match [A-Z]{5}[0-9]{4}[A-Z] (e.g. ABCDE1234F).", False)
            )
        else:
            issues.append(ValidationIssue("pan_regex", "PAN regex structure matched.", True))
            code = pan[3]
            holder_type = PAN_TYPE_CODES.get(code)
            if holder_type is None:
                issues.append(
                    ValidationIssue(
                        "pan_type",
                        f"Invalid type code '{code}' at 4th character. Expected one of {', '.join(PAN_TYPE_CODES)}.",
                        False,
                    )
                )
            else:
                issues.append(ValidationIssue("pan_type", f"Holder type code '{code}' = {holder_type}.", True))
        issues.extend(_common_field_checks(name, dob, required_id=bool(pan)))
        id_valid = all(i.passed for i in issues if i.code in {"pan_regex", "pan_type"})
        return ValidationResult("PAN", id_valid, issues, holder_type)


class GenericValidator(DocumentValidator):
    document_type = "GENERIC"

    def validate(self, id_number: Optional[str], name: Optional[str], dob: Optional[str]) -> ValidationResult:
        issues = _common_field_checks(name, dob, required_id=True)
        if not id_number:
            issues.append(ValidationIssue("id_missing", "No ID number could be extracted.", False))
        else:
            issues.append(ValidationIssue("id_present", "Generic ID number captured (no type-specific checksum).", True))
        id_valid = bool(id_number) and all(i.passed or i.code not in {"id_missing"} for i in issues)
        return ValidationResult("GENERIC", bool(id_number), issues)


VALIDATORS: dict[str, DocumentValidator] = {
    "AADHAAR": AadhaarValidator(),
    "PAN": PANValidator(),
    "GENERIC": GenericValidator(),
}


def detect_document_type(text: str, id_number: Optional[str] = None) -> str:
    blob = f"{text} {id_number or ''}".upper()
    if "AADHAAR" in blob or "UIDAI" in blob or "UNIQUE IDENTIFICATION" in blob:
        return "AADHAAR"
    if "PAN" in blob or "INCOME TAX" in blob or "PERMANENT ACCOUNT" in blob:
        return "PAN"
    if id_number and re.fullmatch(r"\d{12}", re.sub(r"\D", "", id_number)):
        return "AADHAAR"
    if id_number and PAN_REGEX.match(re.sub(r"\s", "", id_number).upper()):
        return "PAN"
    return "GENERIC"


def validate_document(
    document_type: str, id_number: Optional[str], name: Optional[str], dob: Optional[str]
) -> ValidationResult:
    validator = VALIDATORS.get(document_type, VALIDATORS["GENERIC"])
    return validator.validate(id_number, name, dob)


def _common_field_checks(name: Optional[str], dob: Optional[str], required_id: bool) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not name or len(name.strip()) < 3:
        issues.append(ValidationIssue("name", "Name field missing or implausible.", False))
    elif not re.search(r"[A-Za-z]{2,}", name):
        issues.append(ValidationIssue("name", "Name does not look like a plausible person/org name.", False))
    else:
        issues.append(ValidationIssue("name", f"Name field present ({name.strip()[:40]}).", True))

    if not dob:
        issues.append(ValidationIssue("dob", "Date of birth missing.", False))
    elif not _dob_plausible(dob):
        issues.append(ValidationIssue("dob", f"DOB '{dob}' is not a plausible calendar date.", False))
    else:
        issues.append(ValidationIssue("dob", f"DOB format accepted ({dob}).", True))
    return issues


def _dob_plausible(dob: str) -> bool:
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(dob.replace(".", "/"), fmt)
            return 1920 <= dt.year <= datetime.now().year
        except ValueError:
            continue
    return False
