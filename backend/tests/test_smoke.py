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
