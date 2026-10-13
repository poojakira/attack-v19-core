# Third-Party Notices

Owner-controlled new releases are proposed under the proprietary [LICENSE](LICENSE). Versions previously published under MIT retain their existing rights; the former text is preserved in [docs/license-history/LICENSE-BEFORE-2026-10-13.txt](docs/license-history/LICENSE-BEFORE-2026-10-13.txt). These terms do not supersede the independent rights and obligations below.

## MITRE ATT&CK

The repository does not commit or redistribute ATT&CK STIX bundles. The downloader retrieves exact files from MITRE's public `attack-stix-data` repository and verifies pinned SHA-256 hashes.

MITRE ATT&CK is a registered trademark of The MITRE Corporation. Use of ATT&CK data and branding is subject to MITRE's terms:

- https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
- https://github.com/mitre-attack/attack-stix-data

## Python dependencies

Runtime and tool dependencies are listed in `pyproject.toml` and resolved in `uv.lock`. Their licenses are governed by their respective projects. The generated SBOM is a CI artifact and should be reviewed before redistribution or deployment.
