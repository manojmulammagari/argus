# Contributing to ARGUS

Thanks for your interest in ARGUS.

## Dev Setup

```bash
git clone https://github.com/manojmulammagari/argus.git
cd argus
make install
```

Requires Python 3.13, Node 20+, and (optionally) Docker for Postgres/Redis.

## Running Locally

```bash
make run      # starts backend (:8000) and frontend (:3000)
make test     # runs backend test suite
make build    # production build check for the frontend
```

## Branching & PRs

- Branch from `main`: `feature/short-description` or `fix/short-description`.
- Keep PRs focused — one logical change per PR.
- Run `make test` and `make build` locally before opening a PR; CI runs both automatically.
- Describe *what* changed and *why* in the PR description.

## Code Style

- Python: type hints on function signatures, f-strings, no bare `except:`.
- TypeScript: strict mode, avoid `any` unless unavoidable.

## Reporting Bugs

Open a GitHub issue with repro steps. For security vulnerabilities, see [`SECURITY.md`](SECURITY.md) instead of a public issue.
