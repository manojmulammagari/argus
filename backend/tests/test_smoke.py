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


def test_google_genai_sdk_migration():
    """
    Regression for F-001: Ensure deprecated google.generativeai package is NOT imported.
    google.genai should be used instead.
    """
    import sys
    assert "google.generativeai" not in sys.modules, (
        "Deprecated google.generativeai package is loaded! Must use google.genai."
    )
    import main_api
    assert hasattr(main_api, "gemini_client")


def test_admission_control_concurrency_limit():
    """
    Regression for F-008: When active scan count reaches _MAX_CONCURRENT_SCANS,
    new requests must be rejected immediately with 429.
    """
    from fastapi.testclient import TestClient
    import main_api

    client = TestClient(app)
    orig_count = main_api._active_scan_count
    orig_last = main_api._last_scan_started_at
    try:
        # Simulate that max concurrent scans are already running
        main_api._active_scan_count = main_api._MAX_CONCURRENT_SCANS
        main_api._last_scan_started_at = 0  # bypass cooldown check

        resp = client.post("/api/demo")
        assert resp.status_code == 429
        assert "Too many scans" in resp.json()["detail"]
    finally:
        main_api._active_scan_count = orig_count
        main_api._last_scan_started_at = orig_last


def test_extract_diff_files():
    from main_api import extract_diff_files
    diff = """diff --git a/src/index.ts b/src/index.ts
index 1234..5678 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,3 +1,3 @@
-const x = 1;
+const x = 2;
diff --git a/packages/core/api.py b/packages/core/api.py
--- a/packages/core/api.py
+++ b/packages/core/api.py
"""
    files = extract_diff_files(diff)
    assert "src/index.ts" in files
    assert "packages/core/api.py" in files
    assert len(files) == 2


def test_scan_request_payload_aliases():
    from main_api import ScanRequest
    req1 = ScanRequest(repo="acme/widgets", pr_number=1337)
    assert req1.get_repo() == "acme/widgets"
    assert req1.get_pr_number() == 1337

    req2 = ScanRequest(repo_full_name="acme/widgets", pr_number=1337)
    assert req2.get_repo() == "acme/widgets"
    assert req2.get_pr_number() == 1337

    req3 = ScanRequest()
    assert req3.get_repo() == "demo/vulnerable-app"
    assert req3.get_pr_number() == 42


def test_new_scan_start_routes():
    paths = {route.path for route in app.routes}
    assert "/api/scan" in paths
    assert "/api/scan/start" in paths
    assert "/scan/start" in paths


def test_compute_risk_score_bands():
    """
    F-103: uncorroborated ThreatMind findings must never block a merge, and
    confirmed critical/high findings must always land in the block band.
    """
    from main_api import compute_risk_score

    # Solo, uncorroborated ThreatMind speculation -> SAFE band
    risk, _ = compute_risk_score([{"severity": "high"}, {"severity": "critical"}],
                                 uncorroborated_only=True)
    assert risk <= 15, risk

    # Corroborated critical finding -> BLOCK MERGE band
    risk, counts = compute_risk_score([{"severity": "critical"}])
    assert 75 <= risk <= 95, risk
    assert counts["critical"] == 1

    # Clean diff -> zero risk
    risk, _ = compute_risk_score([])
    assert risk == 0

    # A couple of medium findings -> review band, never critical
    risk, _ = compute_risk_score([{"severity": "medium"}, {"severity": "medium"}])
    assert risk <= 45


def test_json_content_replies_are_accepted():
    """F-101: Groq plain-JSON content replies must parse instead of raising."""
    from main_api import _coerce_findings, _extract_json_payload

    assert _coerce_findings([{"a": 1}]) == [{"a": 1}]
    assert _coerce_findings({"findings": [{"a": 1}]}) == [{"a": 1}]
    assert _coerce_findings({"title": "x"}) == [{"title": "x"}]
    assert _coerce_findings("not json") is None
    fenced = _extract_json_payload('Sure:\n```json\n[{"title": "SQLi"}]\n```')
    assert fenced == [{"title": "SQLi"}]


def test_status_line_strips_raw_json_noise():
    """F-101: raw JSON fragments must never reach the SSE thought stream."""
    from main_api import _clean_status_line

    assert _clean_status_line('"findings": []') is None
    assert _clean_status_line("{") is None
    assert _clean_status_line("@@ -1,2 +1,2 @@") is None
    assert _clean_status_line("```json") is None
    assert _clean_status_line("Analyzing added lines for injection sinks") == \
        "Analyzing added lines for injection sinks"


def test_compliance_controls_map_to_real_cwes():
    """F-104: Breach Oracle CWE badges must never render blank."""
    from main_api import compliance_to_cwe

    assert compliance_to_cwe("SOC2", "CC6.1") == "CWE-798"
    assert compliance_to_cwe("SOC2", "CC6.6") == "CWE-89"
    assert compliance_to_cwe("HIPAA", "164.312(b)") == "CWE-532"
    assert compliance_to_cwe("PCI-DSS", "6.3.1") == "CWE-89"
    # An unknown control still resolves via the framework default (never blank)
    assert compliance_to_cwe("SOC2", "CC9.9") == "CWE-798"


def test_fallback_patch_is_always_a_valid_unified_diff():
    """F-102: RemedyBot must always emit a reviewable patch, even with no LLM."""
    from main_api import _build_fallback_patch, _looks_like_diff

    diff = (
        "diff --git a/.github/scripts/docker-create.sh b/.github/scripts/docker-create.sh\n"
        "+++ b/.github/scripts/docker-create.sh\n"
        "@@ -1 +1 @@\n"
        "+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIexampleK7MDENGbPxRfiCY\n"
    )
    findings = [{"severity": "CRITICAL", "title": "Secret in build script",
                 "file_path": ".github/scripts/docker-create.sh",
                 "remediation": "Rotate and load from a secrets manager", "line_number": 1}]

    non_secret = _build_fallback_patch(findings, ["README.md"], "")
    assert _looks_like_diff(non_secret)

    secret_patch = _build_fallback_patch(findings, [".github/scripts/docker-create.sh"], diff)
    assert _looks_like_diff(secret_patch)
    assert "hardcoded secret removed" in secret_patch


def test_extract_added_lines_groups_by_file():
    """F-105: added-line extraction powers the deterministic fallback patch."""
    from main_api import _extract_added_lines

    diff = ("+++ b/Dockerfile\n@@ -1 +1 @@\n+ENV TOKEN=abc\n"
            "+++ b/src/app.py\n@@ -1 +1 @@\n+print('hi')\n")
    added = _extract_added_lines(diff)
    assert added["Dockerfile"] == ["ENV TOKEN=abc"]
    assert added["src/app.py"] == ["print('hi')"]


def test_normalize_finding_guarantees_render_safe_fields():
    """Every finding must be render-safe: no empty title, CWE, file or line."""
    from main_api import normalize_finding

    valid_files = ["src/app.py", "Dockerfile"]
    f = normalize_finding({
        "title": "",
        "severity": "weird",
        "cwe_id": "not-a-cwe",
        "file_path": "src/app.py",
        "line_number": 0,
        "description": "",
    }, "AST Sentinel", valid_files)
    assert f is not None
    assert f["title"] == "Security Policy Violation"
    assert f["severity"] == "MEDIUM"
    assert f["cwe_id"] == "CWE-200"
    assert f["file_path"] in valid_files
    assert f["line_number"] == 1
    assert f["description"] and f["remediation"]
    assert f["agent"] == "AST Sentinel"

    # Fuzzy path resolves to an actual file from the diff
    g = normalize_finding({"title": "SQLi", "severity": "HIGH", "cwe_id": "CWE-89",
                           "file_path": "app.py", "line_number": 12},
                          "Policy Guard", valid_files)
    assert g is not None
    assert g["file_path"] == "src/app.py"
    assert g["cwe_id"] == "CWE-89"
    assert g["severity"] == "HIGH"

    # Compliance CWE prefixes are accepted as-is
    c = normalize_finding({"title": "Log leak", "severity": "LOW", "cwe_id": "SOC2-CC6.7",
                           "file_path": "src/app.py", "line_number": 3},
                          "Policy Guard", valid_files)
    assert c is not None
    assert c["cwe_id"] == "SOC2-CC6.7"

    # Non-dict input is rejected, never crashes
    assert normalize_finding("garbage", "AST Sentinel", valid_files) is None


def test_dedupe_findings_merges_agents_by_line_and_cwe():
    """Same (file, line) OR (file, cwe) collapses into one card listing every agent."""
    from main_api import dedupe_findings

    a = {"id": "1", "agent": "AST Sentinel", "file_path": "src/app.py", "line_number": 10,
         "cwe_id": "CWE-89", "severity": "HIGH", "description": "sqli", "remediation": "fix"}
    b = {"id": "2", "agent": "Policy Guard", "file_path": "src/app.py", "line_number": 10,
         "cwe_id": "SOC2-CC6.6", "severity": "MEDIUM", "description": "policy", "remediation": "fix2"}
    c = {"id": "3", "agent": "Arch Auditor", "file_path": "src/app.py", "line_number": 99,
         "cwe_id": "CWE-89", "severity": "LOW", "description": "same cwe, other line", "remediation": "fix3"}

    out = dedupe_findings([a, b, c])
    assert len(out) == 1
    assert out[0]["agent"] == "AST Sentinel + Policy Guard + Arch Auditor"
    assert out[0]["severity"] == "HIGH"   # highest severity wins the merge
    assert out[0]["id"]

    # A genuinely distinct finding survives as its own card
    d = {"id": "4", "agent": "ThreatMind", "file_path": "Dockerfile", "line_number": 2,
         "cwe_id": "CWE-798", "severity": "CRITICAL", "description": "secret", "remediation": "rotate"}
    assert len(dedupe_findings([a, d])) == 2


def test_build_numbered_diff_uses_real_line_numbers():
    """Agents must see `file_path:line +code` with the REAL new-file line numbers."""
    from main_api import build_numbered_diff

    diff = (
        "diff --git a/src/api.py b/src/api.py\n"
        "--- a/src/api.py\n"
        "+++ b/src/api.py\n"
        "@@ -10,2 +10,3 @@\n"
        " ctx = 1\n"
        "-old = 2\n"
        '+cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        "+token = os.getenv(\"API_TOKEN\")\n"
        " ctx2 = 3\n"
    )
    numbered = build_numbered_diff(diff)
    assert "src/api.py:11 +cursor.execute" in numbered
    assert "src/api.py:12 +token = os.getenv" in numbered
    # Removed (-) lines never appear in the numbered payload
    assert "-old = 2" not in numbered


def test_validate_repo_format():
    from main_api import validate_repo_format

    assert validate_repo_format("acme/widgets")
    assert validate_repo_format("owner-name/repo.name")
    assert not validate_repo_format("just-a-name")
    assert not validate_repo_format("owner/repo/extra")
    assert not validate_repo_format("owner /repo")
    assert not validate_repo_format("")


def test_invalid_repo_format_returns_400():
    """Invalid `owner/repo` slugs must be rejected at request time with HTTP 400."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    resp = client.post("/api/demo", json={"repo": "not-a-repo", "pr_number": 5})
    assert resp.status_code == 400
    assert "owner/repo" in resp.json()["detail"]


def test_llm_tool_call_returns_none_when_all_engines_fail():
    """F-101: a total engine failure must signal `None` (degraded), never `[]` (clean)."""
    import asyncio
    import main_api

    async def run():
        try:
            async def boom(*_a, **_k):
                raise RuntimeError("rate limit exceeded 429")

            main_api._groq_structured_call = boom  # type: ignore[assignment]
            return await main_api.llm_tool_call(
                "test-scan", "ast_sentinel", "prompt", "tool", "desc", {"type": "object"})
        finally:
            main_api._groq_structured_call = original  # type: ignore[assignment]

    original = main_api._groq_structured_call
    had_groq, had_gemini = main_api.groq_client, main_api.gemini_model
    main_api.groq_client, main_api.gemini_model = object(), None
    try:
        assert asyncio.run(run()) is None
    finally:
        main_api.groq_client, main_api.gemini_model = had_groq, had_gemini
        main_api._groq_structured_call = original  # type: ignore[assignment]


def test_gemini_fallback_models_configured():
    import main_api
    assert hasattr(main_api, "GEMINI_FALLBACK_MODELS")
    assert len(main_api.GEMINI_FALLBACK_MODELS) >= 2
    assert "gemini-3.8-flash" in main_api.GEMINI_FALLBACK_MODELS


def test_groq_429_backoff_retry_succeeds():
    """Verify that Groq rate-limit bursts (429) trigger exponential backoff and retry."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock
    import main_api

    attempts = 0

    class MockChatCompletions:
        async def create(self, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("429 rate_limit_exceeded: rate limit reached")
            
            # Second attempt succeeds
            mock_choice = MagicMock()
            mock_choice.message.content = '{"analysis_trace": ["line 1 verified"], "findings": []}'
            mock_choice.message.tool_calls = []
            mock_resp = MagicMock()
            mock_resp.choices = [mock_choice]
            return mock_resp

    mock_groq = MagicMock()
    mock_groq.chat.completions = MockChatCompletions()

    had_groq = main_api.groq_client
    main_api.groq_client = mock_groq
    try:
        res = asyncio.run(main_api._groq_structured_call(
            "test-scan", "ast_sentinel", "prompt", "test_tool", "desc", {"type": "object"}
        ))
        assert attempts == 2, f"Expected 2 attempts with backoff, got {attempts}"
        assert res is not None
        traces, findings = res
        assert findings == []
    finally:
        main_api.groq_client = had_groq


def test_gemini_model_fallback_on_429():
    """Verify that if primary Gemini model throws 429/quota, fallback model is tried."""
    import asyncio
    from unittest.mock import MagicMock
    import main_api

    called_models = []

    class MockGeminiModels:
        def generate_content(self, model, contents, **kwargs):
            called_models.append(model)
            if len(called_models) == 1:
                raise RuntimeError("429 RESOURCE_EXHAUSTED: quota limit 20 reached")
            # Fallback model succeeds
            mock_resp = MagicMock()
            mock_resp.text = '{"analysis_trace": ["line 2 checked"], "findings": []}'
            return mock_resp

    mock_gemini = MagicMock()
    mock_gemini.models = MockGeminiModels()

    had_gemini = main_api.gemini_client
    had_models = list(main_api.GEMINI_FALLBACK_MODELS)
    main_api.gemini_client = mock_gemini
    main_api.GEMINI_FALLBACK_MODELS = ["gemini-test-primary", "gemini-test-secondary"]
    try:
        res = asyncio.run(main_api._call_gemini_unified(
            "test-scan", "threat_mind", "prompt", tool_schema={"type": "object"}
        ))
        assert len(called_models) >= 2, f"Expected multiple models called, got {called_models}"
        assert called_models[0] == "gemini-test-primary"
        assert called_models[1] == "gemini-test-secondary"
        assert res is not None
        traces, findings = res
        assert findings == []
    finally:
        main_api.gemini_client = had_gemini
        main_api.GEMINI_FALLBACK_MODELS = had_models


def test_fail_closed_when_analysis_agents_fail():
    """
    Vulnerability fix: If all analysis agents fail (e.g. Groq 429 + Gemini rate limit),
    the scan MUST NOT return 'SECURITY CHECK PASSED' with risk_score 0!
    It must fail closed into 'SCAN INCOMPLETE / ANALYSIS FAILED' or 'SCAN DEGRADED'.
    """
    import asyncio
    import main_api

    scan_id = "test-fail-closed"
    main_api.SCANS[scan_id] = {
        "id": scan_id,
        "events": [],
        "findings": [],
        "done": False,
        "status": "running",
    }

    # Simulate all LLMs failing
    had_groq, had_gemini = main_api.groq_client, main_api.gemini_model
    main_api.groq_client, main_api.gemini_model = None, None

    try:
        asyncio.run(main_api.run_full_scan(scan_id, "diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -1 +1 @@\n+x=1\n"))
        scan_result = main_api.SCANS[scan_id]

        assert scan_result["status"] in ("error", "degraded", "failed"), f"Got status {scan_result['status']}"
        assert scan_result["verdict"] != "SECURITY CHECK PASSED", "Vulnerability regression: Failed scan marked as passed!"
        assert "FAILED" in scan_result["verdict"] or "DEGRADED" in scan_result["verdict"]
        assert len(scan_result.get("failed_agents", [])) > 0
        consensus = scan_result.get("consensus", {})
        assert consensus.get("agents_total") == 6
        assert consensus.get("is_degraded") is True
    finally:
        main_api.groq_client, main_api.gemini_model = had_groq, had_gemini
        main_api.SCANS.pop(scan_id, None)


def test_degraded_scan_verdict_when_some_agents_fail():
    """
    If 1 or more analysis agents fail but not all, scan verdict must be
    'SCAN DEGRADED' and consensus metrics must accurately reflect completed vs failed.
    """
    import asyncio
    import main_api

    scan_id = "test-partial-degraded"
    main_api.SCANS[scan_id] = {
        "id": scan_id,
        "events": [],
        "findings": [],
        "done": False,
        "status": "running",
    }

    # Mock ast_sentinel returning findings, but policy_guard failing (None)
    had_groq, had_gemini = main_api.groq_client, main_api.gemini_model
    
    async def mock_llm_tool_call(scan_id, agent, prompt, tool_name, tool_desc, tool_schema):
        if agent == "ast_sentinel":
            return ["verified line 1"], []
        # Other analysis agents fail
        return None

    orig_llm = main_api.llm_tool_call
    main_api.llm_tool_call = mock_llm_tool_call
    try:
        asyncio.run(main_api.run_full_scan(scan_id, "diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -1 +1 @@\n+x=1\n"))
        scan_result = main_api.SCANS[scan_id]

        assert scan_result["status"] == "degraded"
        assert scan_result["verdict"] == "SCAN DEGRADED"
        assert "policy_guard" in scan_result["failed_agents"]
        assert "ast_sentinel" in scan_result["completed_agents"]
        consensus = scan_result["consensus"]
        assert consensus["is_degraded"] is True
        assert consensus["agents_total"] == 6
        assert consensus["agents_failed"] >= 1
    finally:
        main_api.llm_tool_call = orig_llm
        main_api.groq_client, main_api.gemini_model = had_groq, had_gemini
        main_api.SCANS.pop(scan_id, None)


def test_is_lockfile_or_generated():
    from main_api import _is_lockfile_or_generated
    assert _is_lockfile_or_generated("package-lock.json") is True
    assert _is_lockfile_or_generated("yarn.lock") is True
    assert _is_lockfile_or_generated("frontend/package-lock.json") is True
    assert _is_lockfile_or_generated("assets/logo.svg") is True
    assert _is_lockfile_or_generated("static/bundle.min.js") is True
    assert _is_lockfile_or_generated("node_modules/foo/index.js") is True
    assert _is_lockfile_or_generated("src/auth.py") is False
    assert _is_lockfile_or_generated("components/Button.tsx") is False


def test_filter_diff_for_llm_strips_lockfiles():
    from main_api import filter_diff_for_llm
    diff = (
        "diff --git a/package-lock.json b/package-lock.json\n"
        "+++ b/package-lock.json\n"
        "@@ -1,3 +1,3 @@\n"
        "+  \"version\": \"2.0.0\"\n"
        "diff --git a/src/index.ts b/src/index.ts\n"
        "+++ b/src/index.ts\n"
        "@@ -1,2 +1,2 @@\n"
        "+const apiKey = process.env.API_KEY;\n"
    )
    filtered, stats = filter_diff_for_llm(diff)
    assert stats["ignored_lockfiles_count"] == 1
    assert "package-lock.json" not in filtered
    assert "src/index.ts" in filtered


def test_evidence_verification_gate_drops_hallucinations():
    from main_api import _build_valid_files_map, _verify_findings

    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,1 +10,2 @@\n"
        "+eval(user_input)\n"
        "+print('done')\n"
    )
    valid_map = _build_valid_files_map(diff)
    assert "src/app.py" in valid_map
    assert 10 in valid_map["src/app.py"]
    assert 11 in valid_map["src/app.py"]

    findings = [
        {"file_path": "src/app.py", "line_number": 10, "title": "eval sink", "severity": "CRITICAL"},
        {"file_path": "src/app.py", "line_number": 99, "title": "fake line", "severity": "HIGH"},
        {"file_path": "nonexistent.py", "line_number": 10, "title": "fake file", "severity": "HIGH"},
    ]
    verified = _verify_findings(findings, valid_map)
    assert len(verified) == 1
    assert verified[0]["line_number"] == 10
    assert verified[0]["code_snippet"] == "eval(user_input)"
