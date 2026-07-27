# Runbook

## Engineering Update - 2026-07-27

Repository: attack-v19-core
Purpose: Private MITRE ATT&CK v19.1 mapping core

## Build

- Install: make install
- Lint: make lint
- Format: make format
- Test: make test
- Package build: make build
- Security scan: make security
- Full local gate: make verify

## Dashboard

Static 3D dashboard: dashboard/index.html. Serve with make dashboard after local static validation.

## Dependencies And Data

Downloads pinned MITRE ATT&CK v19.1 STIX bundles with SHA-256 verification.

## Validation Snapshot

Validated: Ruff passed, pytest passed (52 tests), wheel build passed.

## Operating Limits

- Re-check Linux and GitHub Actions after pushing to main.
- Treat local dashboard scores as evidence indicators, not certifications.
- Do not cite production readiness until clean CI, dependency audit, license status, and runtime smoke tests are current.