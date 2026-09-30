# Security Audit — attack-v19-core

**Audit date:** 2026-09-29  
**Scope:** ATT&CK data downloader, local STIX loading, CLI/file handling, dependencies, workflows, and supply-chain integrity.

## Executive summary

This repository is a local data library/CLI rather than an authenticated web application. User UUIDs, password-reset links, SQL injection, XSS, admin routes, API throttling, payment handling, and blue/green web deployment are not applicable.

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| ATTACK-001 | Info | Downloader is the principal network trust boundary; it uses an explicit host allowlist and strict redirect handling. | Verified |
| ATTACK-002 | Low | Local bundle integrity is verified by default on load against pinned SHA-256 values; downloads are HTTPS/host/redirect/size constrained and STIX structure is validated before replacement. Operators can explicitly disable loader integrity verification, so that opt-out remains an operational trust decision. | Verified |
| ATTACK-003 | Info | No web/database/authentication surface exists. | N/A |

## Existing controls verified

- Download-host allowlist.
- Redirect restrictions.
- Bundle-size/integrity validation code.
- Bounded local file loading.
- Pinned CI actions and dependency workflows.
- Secret-hygiene CI.

## Verification plan

Run the repository test/production workflows and re-check downloader host, redirect, size, and integrity tests.
