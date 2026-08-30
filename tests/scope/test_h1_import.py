from __future__ import annotations

import json

from gesicht.core.models import ScopeType
from gesicht.scope import h1_import

H1_JSON = json.dumps(
    {
        "data": [
            {
                "id": "1",
                "type": "structured-scope",
                "attributes": {
                    "asset_identifier": "*.example.com",
                    "asset_type": "WILDCARD",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                    "max_severity": "critical",
                    "instruction": "Test everything",
                },
            },
            {
                "attributes": {
                    "asset_identifier": "https://legacy.example.com",
                    "asset_type": "URL",
                    "eligible_for_submission": False,
                    "eligible_for_bounty": False,
                }
            },
            {
                "attributes": {
                    "asset_identifier": "com.example.android",
                    "asset_type": "GOOGLE_PLAY_APP_ID",
                    "eligible_for_submission": True,
                }
            },
        ]
    }
)


def test_structured_json_maps_types_and_eligibility():
    scope = h1_import.from_structured_json(H1_JSON, handle="example")
    by_val = {e.value: e for e in scope.entries}

    assert by_val["*.example.com"].type == ScopeType.WILDCARD
    assert by_val["*.example.com"].max_severity == "critical"
    assert by_val["*.example.com"].in_scope is True

    assert by_val["https://legacy.example.com"].in_scope is False  # not eligible for submission
    assert by_val["com.example.android"].type == ScopeType.MOBILE_APP
    assert scope.imported_from == "h1-api"


def test_pasted_text_best_effort():
    pasted = """\
In scope
*.example.com
api.example.com\tURL
# a comment
10.0.0.0/24
"""
    scope = h1_import.from_pasted_text(pasted, handle="example")
    vals = {e.value: e for e in scope.entries}
    assert vals["*.example.com"].type == ScopeType.WILDCARD
    assert vals["api.example.com"].type == ScopeType.URL  # forced by 2nd column
    assert vals["10.0.0.0/24"].type == ScopeType.CIDR
    assert "# a comment" not in vals
