"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path


class JSONReporter:
    def write(self, report: dict, path: str) -> None:
        Path(path).write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )
