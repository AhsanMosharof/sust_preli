"""
test_schema.py — Schema compliance and input validation tests.
Validates that the API correctly rejects malformed inputs (edge_cases.md §1).
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

VALID_BASE = {
    "ticket_id": "TEST-001",
    "complaint": "I need help with my account",
    "transaction_history": [],
}


class TestRequiredFields:
    def test_missing_ticket_id_returns_422(self):
        r = client.post("/analyze-ticket", json={"complaint": "help"})
        assert r.status_code in (400, 422), f"Got {r.status_code}"

    def test_missing_complaint_returns_422(self):
        r = client.post("/analyze-ticket", json={"ticket_id": "T1"})
        assert r.status_code in (400, 422)

    def test_empty_complaint_returns_422(self):
        r = client.post("/analyze-ticket", json={"ticket_id": "T1", "complaint": ""})
        assert r.status_code in (400, 422)

    def test_whitespace_complaint_returns_422(self):
        r = client.post("/analyze-ticket", json={"ticket_id": "T1", "complaint": "   "})
        assert r.status_code in (400, 422)

    def test_empty_ticket_id_returns_422(self):
        r = client.post("/analyze-ticket", json={"ticket_id": "", "complaint": "help"})
        assert r.status_code in (400, 422)


class TestInvalidJSON:
    def test_invalid_json_body(self):
        r = client.post(
            "/analyze-ticket",
            data="not json at all",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code in (400, 422)

    def test_empty_body(self):
        r = client.post(
            "/analyze-ticket",
            data="{}",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code in (400, 422)


class TestResponseSchema:
    REQUIRED_FIELDS = [
        "ticket_id", "relevant_transaction_id", "evidence_verdict",
        "case_type", "severity", "department", "agent_summary",
        "recommended_next_action", "customer_reply", "human_review_required",
    ]

    VALID_VERDICTS   = {"consistent", "inconsistent", "insufficient_data"}
    VALID_CASE_TYPES = {
        "wrong_transfer", "payment_failed", "refund_request", "duplicate_payment",
        "merchant_settlement_delay", "agent_cash_in_issue",
        "phishing_or_social_engineering", "other",
    }
    VALID_SEVERITIES  = {"low", "medium", "high", "critical"}
    VALID_DEPARTMENTS = {
        "customer_support", "dispute_resolution", "payments_ops",
        "merchant_operations", "agent_operations", "fraud_risk",
    }

    def get_valid_response(self):
        r = client.post("/analyze-ticket", json=VALID_BASE)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        return r.json()

    def test_all_required_fields_present(self):
        data = self.get_valid_response()
        for field in self.REQUIRED_FIELDS:
            assert field in data, f"Missing required field: '{field}'"

    def test_ticket_id_echoed(self):
        data = self.get_valid_response()
        assert data["ticket_id"] == VALID_BASE["ticket_id"]

    def test_evidence_verdict_valid_enum(self):
        data = self.get_valid_response()
        assert data["evidence_verdict"] in self.VALID_VERDICTS, \
            f"Invalid evidence_verdict: {data['evidence_verdict']}"

    def test_case_type_valid_enum(self):
        data = self.get_valid_response()
        assert data["case_type"] in self.VALID_CASE_TYPES, \
            f"Invalid case_type: {data['case_type']}"

    def test_severity_valid_enum(self):
        data = self.get_valid_response()
        assert data["severity"] in self.VALID_SEVERITIES, \
            f"Invalid severity: {data['severity']}"

    def test_department_valid_enum(self):
        data = self.get_valid_response()
        assert data["department"] in self.VALID_DEPARTMENTS, \
            f"Invalid department: {data['department']}"

    def test_human_review_required_is_bool(self):
        data = self.get_valid_response()
        assert isinstance(data["human_review_required"], bool), \
            f"human_review_required should be bool, got {type(data['human_review_required'])}"

    def test_no_http_500_on_valid_input(self):
        r = client.post("/analyze-ticket", json=VALID_BASE)
        assert r.status_code != 500, "Got HTTP 500 on valid input"

    def test_extra_fields_in_request_accepted(self):
        """Unknown fields should be silently ignored (edge_cases.md §1.9)."""
        payload = {**VALID_BASE, "unknown_field_xyz": "ignored"}
        r = client.post("/analyze-ticket", json=payload)
        assert r.status_code == 200

    def test_null_transaction_history_accepted(self):
        """null transaction_history should be treated as empty list (edge_cases.md §1.10)."""
        payload = {**VALID_BASE, "transaction_history": None}
        r = client.post("/analyze-ticket", json=payload)
        assert r.status_code == 200
