from __future__ import annotations

import logging
from dataclasses import dataclass

from .output import Reporter


@dataclass
class Context:
    reporter: Reporter
    logger: logging.Logger
