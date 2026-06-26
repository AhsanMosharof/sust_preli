"""
test_sample_cases.py — Validate all 10 public sample cases.
Each case must return the correct relevant_transaction_id, evidence_verdict,
case_type, and department.
"""

import json
import os

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# Load sample cases from workspace root
SAMPLE_FILE = os.path.join(os.path.dirname(__file__), "..", "SUST_Preli_Sample_Cases.json")

with open(SAMPLE_FILE, encoding="utf-8") as f:
    _data = json.load(f)

SAMPLE_CASES = _data.get("cases", [])


@pytest.mark.parametrize("case", SAMPLE_CASES, ids=[c.get("id", str(i)) for i, c in enumerate(SAMPLE_CASES)])
def test_sample_case(case):
    """
    For each public sample case:
    - HTTP 200 returned
    - ticket_id echoed correctly
    - relevant_transaction_id matches expected
    - evidence_verdict matches expected
    - case_type matches expected
    - department matches expected
    - All required fields present and non-null where expected
    """
    expected = case.get("expected_output", {})
    r = client.post("/analyze-ticket", json=case["input"])

    assert r.status_code == 200, \
        f"Case {case.get('id')}: Expected HTTP 200, got {r.status_code}. Body: {r.text[:200]}"

    data = r.json()

    # ticket_id must be echoed
    assert data.get("ticket_id") == expected.get("ticket_id"), \
        f"Case {case.get('id')}: ticket_id mismatch: got {data.get('ticket_id')}"

    # relevant_transaction_id — critical evidence field
    assert data.get("relevant_transaction_id") == expected.get("relevant_transaction_id"), (
        f"Case {case.get('id')}: relevant_transaction_id mismatch: "
        f"expected={expected.get('relevant_transaction_id')}, "
        f"got={data.get('relevant_transaction_id')}"
    )

    # evidence_verdict
    assert data.get("evidence_verdict") == expected.get("evidence_verdict"), (
        f"Case {case.get('id')}: evidence_verdict mismatch: "
        f"expected={expected.get('evidence_verdict')}, got={data.get('evidence_verdict')}"
    )

    # case_type
    assert data.get("case_type") == expected.get("case_type"), (
        f"Case {case.get('id')}: case_type mismatch: "
        f"expected={expected.get('case_type')}, got={data.get('case_type')}"
    )

    # department
    assert data.get("department") == expected.get("department"), (
        f"Case {case.get('id')}: department mismatch: "
        f"expected={expected.get('department')}, got={data.get('department')}"
    )

    # All required fields present
    required = [
        "ticket_id", "relevant_transaction_id", "evidence_verdict",
        "case_type", "severity", "department", "agent_summary",
        "recommended_next_action", "customer_reply", "human_review_required",
    ]
    for field in required:
        assert field in data, f"Case {case.get('id')}: missing field '{field}'"

    # customer_reply must not be empty
    assert data.get("customer_reply", "").strip(), \
        f"Case {case.get('id')}: customer_reply is empty"

    # agent_summary must not be empty
    assert data.get("agent_summary", "").strip(), \
        f"Case {case.get('id')}: agent_summary is empty"
