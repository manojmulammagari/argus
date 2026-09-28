# Security Policy

ARGUS scans other people's code for vulnerabilities, so we hold our own to the same standard.

## Supported Versions

Only the latest commit on `main` is supported. This is a hackathon-stage project; no LTS branches exist yet.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use [GitHub's private security advisory feature](https://github.com/manojmulammagari/argus/security/advisories/new) for this repository, or email the maintainer directly.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any relevant logs or proof-of-concept code

We aim to acknowledge reports within 72 hours.

## Scope

This includes vulnerabilities in:
- The FastAPI backend (`backend/`), including the prompt-injection sanitization in `sanitize_diff()`
- The Next.js dashboard (`frontend/`)
- The CI/CD pipeline (`.github/workflows/`)

Vulnerabilities in third-party dependencies (Groq, Gemini, Next.js itself, etc.) should be reported to those projects directly.
