"""Optional CCTNS-style government integration hook — not used in the offline MVP path."""

from abc import ABC, abstractmethod
from typing import Any


class GovernmentKycClient(ABC):
    @abstractmethod
    def verify_identity(self, document_type: str, id_number: str) -> dict[str, Any]:
        """Would call an online KYC/CCTNS-style API. Intentionally unused offline."""


class OfflineNoOpKycClient(GovernmentKycClient):
    def verify_identity(self, document_type: str, id_number: str) -> dict[str, Any]:
        return {
            "invoked": False,
            "reason": "Offline mode: government identity APIs are not called from the verification path.",
            "document_type": document_type,
            "id_suffix": (id_number or "")[-4:],
        }


def default_client() -> GovernmentKycClient:
    return OfflineNoOpKycClient()
