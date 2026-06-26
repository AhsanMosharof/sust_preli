"""
test_health.py — /health endpoint tests.
Must respond within 1 second, always return {"status": "ok"}.
"""

import time

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_200():
    response = client.get("/health")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"


def test_health_returns_correct_body():
    response = client.get("/health")
    assert response.json() == {"status": "ok"}, f"Unexpected body: {response.json()}"


def test_health_fast_response():
    """Health must respond in under 1 second."""
    start = time.time()
    client.get("/health")
    elapsed = time.time() - start
    assert elapsed < 1.0, f"Health too slow: {elapsed:.2f}s"


def test_health_content_type():
    response = client.get("/health")
    assert "application/json" in response.headers.get("content-type", "")
