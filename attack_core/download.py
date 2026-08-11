from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

ATTACK_STIX_TAG = "v19.2"
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
BASE_URL = (
    f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ATTACK_STIX_TAG}"
)
ALLOWED_DOWNLOAD_HOSTS = frozenset({"raw.githubusercontent.com"})

BUNDLES = {
    "enterprise-attack.json": {
        "url": f"{BASE_URL}/enterprise-attack/enterprise-attack.json",
        "sha256": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
    },
    "mobile-attack.json": {
        "url": f"{BASE_URL}/mobile-attack/mobile-attack.json",
        "sha256": "acfa5ca2d93484476f79bf38590e2b55bb675fc0ce85e76bffa0af2c82dada64",
    },
    "ics-attack.json": {
        "url": f"{BASE_URL}/ics-attack/ics-attack.json",
        "sha256": "08b83d2cea6b6d6752468ef0e62e2ab2a53c9443ef72c439ecccb07ab9e89da9",
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, target: Path, *, max_bytes: int = MAX_BUNDLE_BYTES) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError("Bundle URL must use HTTPS on an approved download host")
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    try:
        # The scheme and host are allowlisted immediately above.
        with urlopen(url, timeout=60) as response, tmp.open("wb") as handle:  # nosec B310
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError(
                        f"Download exceeded {max_bytes} bytes; refusing oversized bundle"
                    )
                handle.write(chunk)
        tmp.replace(target)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def ensure_attack_data(data_dir: Path, *, force: bool = False) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    for filename, spec in BUNDLES.items():
        target = data_dir / filename
        expected_hash = spec["sha256"]
        if target.exists() and not force and _sha256(target) == expected_hash:
            print(f"OK {filename}: already present")
            continue
        print(f"Downloading {filename} from {spec['url']}")
        _download(spec["url"], target)
        actual_hash = _sha256(target)
        if actual_hash != expected_hash:
            target.unlink(missing_ok=True)
            raise RuntimeError(
                f"SHA-256 mismatch for {filename}: expected {expected_hash}, got {actual_hash}"
            )
        print(f"OK {filename}: sha256={actual_hash}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download pinned MITRE ATT&CK v19.2 STIX bundles."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path.home() / "attack_data",
        help="Directory where enterprise/mobile/ics ATT&CK JSON bundles are stored.",
    )
    parser.add_argument(
        "--force", action="store_true", help="Re-download even if files exist."
    )
    args = parser.parse_args(argv)
    ensure_attack_data(args.data_dir, force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
