"""Thin wrapper over the ``cvss`` library - validate a vector, get a base score."""

from __future__ import annotations

from dataclasses import dataclass

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from ..core.errors import UsageError

_SEVERITY_BANDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
)


@dataclass(slots=True)
class CvssResult:
    vector: str
    score: float
    severity: str
    version: str


def severity_for_score(score: float) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "info"


# CVSS 3.1 base metrics: (metric, prompt, {choice: label})
_V31_METRICS = [
    ("AV", "Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    ("AC", "Attack Complexity", {"L": "Low", "H": "High"}),
    ("PR", "Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    ("UI", "User Interaction", {"N": "None", "R": "Required"}),
    ("S", "Scope", {"U": "Unchanged", "C": "Changed"}),
    ("C", "Confidentiality Impact", {"N": "None", "L": "Low", "H": "High"}),
    ("I", "Integrity Impact", {"N": "None", "L": "Low", "H": "High"}),
    ("A", "Availability Impact", {"N": "None", "L": "Low", "H": "High"}),
]


def build_cvss31_interactive(prompt=None) -> str:
    """Ask for each CVSS 3.1 base metric and return the vector string.

    ``prompt`` defaults to :func:`typer.prompt`; injectable for tests.
    """
    if prompt is None:
        import typer

        prompt = typer.prompt

    parts = ["CVSS:3.1"]
    for metric, label, choices in _V31_METRICS:
        opts = ", ".join(f"{k}={v}" for k, v in choices.items())
        while True:
            raw = str(prompt(f"{label} [{opts}]", default=next(iter(choices)))).strip().upper()
            if raw in choices:
                parts.append(f"{metric}:{raw}")
                break
    return "/".join(parts)


def parse_cvss(vector: str) -> CvssResult:
    """Validate ``vector`` and return its base score + severity band."""
    v = vector.strip()
    try:
        if v.upper().startswith("CVSS:4"):
            c = CVSS4(v)
            score = float(c.base_score)
            version = "4.0"
        elif v.upper().startswith("CVSS:3"):
            c = CVSS3(v)
            score = float(c.scores()[0])
            version = "3.1" if "3.1" in v else "3.0"
        else:
            c = CVSS2(v)
            score = float(c.scores()[0])
            version = "2.0"
    except (CVSSError, ValueError, KeyError) as e:
        raise UsageError(f"invalid CVSS vector: {e}") from e
    return CvssResult(vector=v, score=round(score, 1), severity=severity_for_score(score),
                      version=version)
