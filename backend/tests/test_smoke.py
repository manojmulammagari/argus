"""
Smoke tests only. Deliberately makes ZERO real calls to Groq, Gemini,
Postgres, or Redis — CI must stay fast, free, and deterministic.
"""
import os

os.environ.setdefault("GROQ_API_KEY", "test-key")
os.environ.setdefault("GEMINI_API_KEY", "test-key")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")

from main_api import app


def test_app_boots():
    """main_api.py must import cleanly with no real credentials present."""
    assert app is not None


def test_frozen_api_contract():
    """
    These paths are the frontend's hard contract with the backend.
    If this fails, something renamed or removed an endpoint the
    Next.js dashboard depends on.

    Verified against main_api.py routes and:
      - frontend/src/app/page.tsx           → POST /api/demo, GET /api/scans
      - frontend/src/app/scan/[id]/page.tsx → GET /api/scans/{scan_id},
                                              GET /api/stream/{scan_id}
    """
    paths = {route.path for route in app.routes}

    # Core endpoints — POST to start a scan, SSE stream to receive events
    assert "/api/demo" in paths
    assert "/api/stream/{scan_id}" in paths

    # Listing and detail — used by page.tsx and scan/[id]/page.tsx respectively
    assert "/api/scans" in paths
    assert "/api/scans/{scan_id}" in paths

    # Approval endpoint — used by the remediation flow
    assert "/api/scans/{scan_id}/approve" in paths
    assert "/health" in paths


def test_normalize_severity():
    from main_api import normalize_severity
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("High") == "high"
    assert normalize_severity("MEDIUM") == "medium"
    assert normalize_severity("low") == "low"
    assert normalize_severity("unknown") == "medium"
    assert normalize_severity(None) == "medium"
    assert normalize_severity(123) == "medium"


def test_health_endpoint():
    from fastapi.testclient import TestClient
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "groq" in data
    assert "gemini" in data


def test_eviction_is_timezone_safe():
    """
    Regression for F-002: A freshly created scan must NOT be evicted.
    Previously, datetime.utcnow().isoformat() was stored and later parsed
    via fromisoformat().timestamp(), which interprets naive datetimes as
    LOCAL time.  At UTC+5:30, a scan created at 09:00 UTC looked like it was
    created at 03:30 UTC (5.5 h in the past) and was immediately evicted.
    Fix: store a UTC epoch float (created_at_ts) and compare directly.
    """
    import time
    from main_api import SCANS, _evict_old_scans

    test_id = "eviction-regression-test"
    SCANS[test_id] = {
        "id": test_id,
        "events": [],
        "findings": [],
        "done": False,
        "created_at_ts": time.time(),           # created NOW
    }
    _evict_old_scans()
    assert test_id in SCANS, (
        "Fresh scan was evicted immediately — timezone eviction bug is back!"
    )
    SCANS.pop(test_id, None)   # clean up


def test_demo_scan_created_at_is_utc():
    """created_at in SCANS must be a timezone-aware ISO-8601 string (ends with +00:00)."""
    from fastapi.testclient import TestClient
    from main_api import SCANS

    client = TestClient(app)
    resp = client.post("/api/demo")
    assert resp.status_code == 200
    scan_id = resp.json()["scan_id"]
    created = SCANS[scan_id]["created_at"]
    assert "+00:00" in created or created.endswith("Z"), (
        f"created_at is not UTC-aware: {created!r}"
    )
    SCANS.pop(scan_id, None)   # clean up
