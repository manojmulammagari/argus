# ARGUS Architecture Notes

## Pipeline

1. A PR diff arrives at `POST /api/demo` (or, in production, a GitHub webhook).
2. `sanitize_diff()` truncates, strips control characters, neutralizes known prompt-injection phrasing, and wraps the result in `<untrusted_diff>` boundary tags.
3. Four agents run concurrently via `asyncio.gather`, each wrapped in a 90-second timeout (`_guarded()`). A hung or failed agent returns `[]` rather than crashing the pipeline.
4. Findings are aggregated, cross-referenced against `BREACH_ORACLE` for historical breach citations, and scored into a 0–100 risk score.
5. `RemedyBot` drafts a patch PR; `Red Team Ω` builds the kill chain.
6. Results stream to the frontend over SSE as they become available — the dashboard never waits for the full pipeline to finish before showing agent progress.

## SSE Event Contract

See the table in the README. `stream_events()` detects client disconnects via `request.is_disconnected()`, sends a heartbeat comment roughly every 10s, and enforces a 90-second **idle** timeout that only counts genuinely idle ticks — not ticks spent draining a backlog of buffered events.

## Design Decisions

- **In-memory `SCANS` dict, not the Postgres schema, drives the live demo path.** `schema.sql` defines persistent tables (`scan_jobs`, `findings`, `agent_traces`, `compliance_rules`, `attack_chains`) for a future durable-history feature — see Roadmap.
- **Per-agent timeouts over one global pipeline timeout.** A global timeout would either cut off agents that are almost done or wait unnecessarily on a single hung one; per-agent timeouts let fast agents finish immediately while slow ones fail in isolation.
- **`orchestrator.py` is not currently imported by `main_api.py`.** It scaffolds a Redis Pub/Sub-based distributed version of the same pipeline — the reference implementation for the Roadmap's "Next" milestone.
