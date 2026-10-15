"""Optional ML forgery detector slot. MVP uses deterministic ELA + rules only."""

from typing import Optional

import numpy as np
from PIL import Image


class OptionalCnnDetector:
    """Placeholder for a future CNN signal. Never replaces Verhoeff/PAN/ELA."""

    enabled: bool = False

    def score(self, image: Image.Image) -> Optional[float]:
        if not self.enabled:
            return None
        arr = np.asarray(image.convert("L"), dtype=np.float32)
        # Deterministic dummy: not a real model — keeps the extension point typed.
        return float(min(1.0, arr.std() / 64.0))
