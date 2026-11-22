"""Local JSON persistence for the paranoia progression.

Only the current score/state, validated transition history and permanent audit
reports are stored, in ``paranoia_state.json`` beside the other SSG8 files.
Writes are atomic. A missing or corrupted file never stops the application:
defaults are used and the problem is reported through :meth:`errors`.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ssg8.services.paranoia.models import AuditReport, ParanoiaTransition
from ssg8.services.paranoia.states import (
    SCORE_MAX,
    ParanoiaState,
    clamp_score,
    state_for_score,
)
from ssg8.storage.protection_store import default_data_root

MAX_TRANSITIONS = 500
MAX_AUDITS = 100


@dataclass(frozen=True, slots=True)
class ParanoiaSnapshot:
    """Everything restored from disk at startup."""

    score: int = 0
    state: ParanoiaState = ParanoiaState.NORMAL
    transitions: tuple[ParanoiaTransition, ...] = ()
    audit_reports: tuple[AuditReport, ...] = ()


class ParanoiaStore:
    """Load and save the demonstration progression."""

    def __init__(self, root: Path | None = None) -> None:
        self._root = Path(root) if root is not None else default_data_root()
        self._errors: list[str] = []

    @property
    def root(self) -> Path:
        return self._root

    @property
    def state_path(self) -> Path:
        return self._root / "paranoia_state.json"

    def errors(self) -> tuple[str, ...]:
        return tuple(self._errors)

    # --- loading -----------------------------------------------------------

    def load(self) -> ParanoiaSnapshot:
        raw = self._read_json(self.state_path, "paranoia state")
        if raw is None:
            return ParanoiaSnapshot()

        if not isinstance(raw, dict):
            self._errors.append("Paranoia state file is not a JSON object; defaults used.")
            return ParanoiaSnapshot()

        score = raw.get("score")
        if isinstance(score, int) and not isinstance(score, bool):
            score = max(0, min(SCORE_MAX, score))
        else:
            if score is not None:
                self._errors.append("Stored paranoia score is invalid; zero used.")
            score = 0

        state_text = raw.get("state")
        try:
            state = ParanoiaState(state_text)
        except (TypeError, ValueError):
            if state_text is not None:
                self._errors.append("Stored paranoia state is invalid; score used.")
            state = state_for_score(score)

        if state.is_numeric and state is not state_for_score(score):
            self._errors.append(
                "Stored paranoia state did not match its score; the score was used."
            )
            state = state_for_score(score)
        score = clamp_score(score)

        transitions: list[ParanoiaTransition] = []
        for index, item in enumerate(_list(raw.get("transitions"))):
            try:
                transitions.append(ParanoiaTransition.from_dict(item))
            except (TypeError, ValueError) as exc:
                self._errors.append(
                    f"Paranoia transition {index + 1} skipped: {exc}"
                )

        audits: list[AuditReport] = []
        for index, item in enumerate(_list(raw.get("audit_reports"))):
            try:
                audits.append(AuditReport.from_dict(item))
            except (TypeError, ValueError) as exc:
                self._errors.append(f"Audit report {index + 1} skipped: {exc}")

        return ParanoiaSnapshot(
            score=score,
            state=state,
            transitions=tuple(transitions[-MAX_TRANSITIONS:]),
            audit_reports=tuple(audits[-MAX_AUDITS:]),
        )

    # --- saving ------------------------------------------------------------

    def save(
        self,
        score: int,
        state: ParanoiaState,
        transitions: tuple[ParanoiaTransition, ...],
        audit_reports: tuple[AuditReport, ...],
    ) -> bool:
        payload = {
            "score": clamp_score(score),
            "state": state.value,
            "transitions": [
                item.to_dict() for item in transitions[-MAX_TRANSITIONS:]
            ],
            "audit_reports": [
                report.to_dict() for report in audit_reports[-MAX_AUDITS:]
            ],
        }
        return self._write_json(self.state_path, payload)

    # --- internals ---------------------------------------------------------

    def _read_json(self, path: Path, label: str) -> Any | None:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._errors.append(f"Could not read {label}: {exc}")
            return None

    def _write_json(self, path: Path, payload: Any) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(
                json.dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
            temporary.replace(path)
            return True
        except (OSError, TypeError, ValueError) as exc:  # pragma: no cover - filesystem
            self._errors.append(f"Could not save paranoia state: {exc}")
            print(f"SSG8: could not save paranoia state: {exc}", file=sys.stderr)
            return False


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
