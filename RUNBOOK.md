# Runbook — ATT&CK v19 Core

Step-by-step guide to build, test, and use the shared ATT&CK v19 data model library.

---

## Step 1: Prerequisites

- Python 3.10+ (`py --version` on Windows, `python3 --version` on Linux)
- pip (bundled with Python)
- Git
- Internet access (for downloading MITRE ATT&CK STIX bundles on first run)

---

## Step 2: Clone

**Windows (PowerShell):**
```powershell
cd C:\Users\pooja\repos
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
```

**Linux/macOS:**
```bash
cd ~/repos
git clone https://github.com/poojakira/attack-v19-core.git
cd attack-v19-core
```

---

## Step 3: Install

**Windows (PowerShell):**
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

**Or use Makefile (if `make` available):**
```powershell
make install
```

---

## Step 4: Download ATT&CK Data

The library uses pinned MITRE ATT&CK v19.1 STIX bundles, verified with SHA-256 checksums.

**Windows (PowerShell):**
```powershell
.\.venv\Scripts\python.exe scripts/download_attack_data.py
```

**Linux/macOS:**
```bash
python scripts/download_attack_data.py
```

Expected output:
```
Downloading ATT&CK Enterprise v19.1...
SHA-256 verified: OK
Downloading ATT&CK Mobile v19.1...
SHA-256 verified: OK
Downloading ATT&CK ICS v19.1...
SHA-256 verified: OK
Data saved to: data/
```

---

## Step 5: Run (Verify Library Works)

The tactic/technique constants load with no STIX download, so they are the
fastest sanity check that the package imported correctly.

**Windows (PowerShell):**
```powershell
# Quick sanity check — the v19 tactic set (no data download needed)
.\.venv\Scripts\python.exe -c "from attack_v19_core import ENTERPRISE_TACTICS; print(f'Loaded {len(ENTERPRISE_TACTICS)} enterprise tactics')"

# List all tactic names
.\.venv\Scripts\python.exe -c "from attack_v19_core import ENTERPRISE_TACTICS; print([name for _, name in ENTERPRISE_TACTICS])"

# CLI: list the v19 revocation map (no data download needed)
.\.venv\Scripts\python.exe -m attack_core revoked
```

**Linux/macOS:**
```bash
python -c "from attack_v19_core import ENTERPRISE_TACTICS; print(f'Loaded {len(ENTERPRISE_TACTICS)} enterprise tactics')"
python -m attack_core revoked
```

Expected output:
```
Loaded 15 enterprise tactics
```

> **Note:** Full technique lookup (`ATTACKIndex`/`ATTACKLoader`) requires the
> STIX bundles from Step 4. The constant above needs no download.

---

## Step 6: Run Tests

**Windows (PowerShell):**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

**Linux/macOS:**
```bash
pytest tests/ -v
```

Expected: 121 tests passing (1 skipped).

**Full verification (lint + test + build + security):**
```powershell
make verify
```

---

## Available Makefile Targets

| Command | What it does |
|---------|-------------|
| `make install` | Install dependencies into venv |
| `make test` | Run pytest (~52 tests) |
| `make lint` | Run ruff linter |
| `make format` | Auto-format with ruff |
| `make build` | Build wheel package |
| `make security` | Run bandit + pip-audit |
| `make verify` | All of the above in sequence |
| `make dashboard` | Serve dashboard at localhost:8080 |

---

## View Dashboard

```powershell
py -m http.server 8080 --directory dashboard
# Open http://localhost:8080
```

Or view hosted: https://poojakira.github.io/mlsec-dashboards/attack-v19-core/

> **Note:** Dashboard is for visual inspection only — not a test artifact.

---

## Usage as a Dependency

Other repos in this portfolio depend on `attack-v19-core`. Install it from the local checkout:

```powershell
# From a sibling repo (e.g., adversarial-ml-lab)
.\.venv\Scripts\python.exe -m pip install -e ..\attack-v19-core
```

Repos that depend on this:
- `adversarial-ml-lab`
- `model-privacy-attacks`
- `llm-redteam-framework`
- `unified-ml-security-platform`

---

## Troubleshooting

### Download Fails (Network Error)

```
ConnectionError: Failed to download ATT&CK bundle
```

**Fix:**
1. Check internet connectivity.
2. Check if MITRE's GitHub is accessible: https://github.com/mitre-attack/attack-stix-data
3. If behind a proxy:
   ```powershell
   $env:HTTPS_PROXY = "http://your-proxy:port"
   .\.venv\Scripts\python.exe scripts/download_attack_data.py
   ```

---

### SHA-256 Checksum Mismatch

```
ValueError: Checksum verification failed
```

**Fix:** The pinned checksums may be outdated if MITRE updated their bundles. Check the script for the expected hashes and compare with the latest release.

---

### Tests Fail with "Data not found"

**Fix:** Run the download script first (Step 4):
```powershell
.\.venv\Scripts\python.exe scripts/download_attack_data.py
```

---

### Tests Pass Locally but Fail in CI

- CI runs on Linux — check for Windows-specific path issues
- Ensure `scripts/download_attack_data.py` runs in CI before tests
- Run `make lint` before pushing

---

## Things to Check Before Pushing

- [ ] Tests pass locally (`make test`)
- [ ] Linter is clean (`make lint`)
- [ ] Wheel builds without errors (`make build`)
- [ ] CI will run on Linux — avoid Windows-only path assumptions

---

## Known Limitations

- Local dashboard scores are informational, not certifications
- Not production-ready without current CI passing + dependency audit
- Data files are pinned to ATT&CK v19.1 — won't auto-update to newer versions
