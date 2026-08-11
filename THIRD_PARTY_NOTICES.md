# Third-Party Notices

This project is licensed under the MIT License in `LICENSE`.

## MITRE ATT&CK

The repository does not commit or redistribute ATT&CK STIX bundles. The downloader retrieves exact files from MITRE's public `attack-stix-data` repository and verifies pinned SHA-256 hashes.

MITRE ATT&CK is a registered trademark of The MITRE Corporation. Use of ATT&CK data and branding is subject to MITRE's terms:

- https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
- https://github.com/mitre-attack/attack-stix-data

## Python dependencies

Runtime and tool dependencies are listed in `pyproject.toml` and resolved in `uv.lock`. Their licenses are governed by their respective projects. The generated SBOM is a CI artifact and should be reviewed before redistribution or deployment.
