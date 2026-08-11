# Security Policy

## Scope

Security fixes are supported on the latest `main` branch. No hosted service or production SLA is provided.

Use GitHub private vulnerability reporting if enabled. If unavailable, open a minimal public issue requesting a private contact channel without vulnerability details. Never post credentials, private STIX extensions, customer data, or exploit payloads publicly.

## Trust boundaries

- Official ATT&CK bundles are downloaded over HTTPS and accepted only when their pinned SHA-256 hashes match.
- Local paths supplied through `ATTACK_DATA_DIR` are operator-controlled and trusted.
- Bundle content is parsed in process by `mitreattack-python`; malformed input can consume application resources or trigger parser defects.
- HTML table output escapes STIX-controlled fields. JSON and CSV consumers remain responsible for destination-specific encoding and formula-injection controls.
- Navigator mapping confidence is caller-supplied metadata, not a measured security score.

## Safe deployment

Run the library as a non-privileged user with read-only access to the verified data directory. Do not allow untrusted users to select arbitrary data paths or replace bundle files. Pin the commit, `uv.lock`, and bundle hashes together.
