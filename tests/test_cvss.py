from __future__ import annotations

import pytest

from gesicht.core.errors import UsageError
from gesicht.report.cvss import parse_cvss, severity_for_score


def test_cvss_v31():
    r = parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert r.score == 7.5 and r.severity == "high" and r.version == "3.1"


def test_cvss_v4():
    r = parse_cvss(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    )
    assert r.version == "4.0" and r.severity in {"high", "critical"}


def test_cvss_invalid_raises_usage_error():
    with pytest.raises(UsageError):
        parse_cvss("CVSS:3.1/AV:BOGUS")


@pytest.mark.parametrize(
    "score,band",
    [(0.0, "info"), (2.0, "low"), (5.5, "medium"), (8.0, "high"), (9.9, "critical")],
)
def test_bands(score, band):
    assert severity_for_score(score) == band
