from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from urllib.request import urlopen

ATTACK_STIX_TAG = "v19.1"
BASE_URL = (
    f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ATTACK_STIX_TAG}"
)

BUNDLES = {
    "enterprise-attack.json": {
        "url": f"{BASE_URL}/enterprise-attack/enterprise-attack.json",
        "sha256": "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3",
    },
    "mobile-attack.json": {
        "url": f"{BASE_URL}/mobile-attack/mobile-attack.json",
        "sha256": "423cbceb604770c8997845151fe7cc4813de01033b8cc50c84dd3bd0d96d8322",
    },
    "ics-attack.json": {
        "url": f"{BASE_URL}/ics-attack/ics-attack.json",
        "sha256": "a91f659d6d03095e84089630b098edb2ed9d5cd5b1ea41369b27846cd32f2a43",
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, target: Path) -> None:
    tmp = target.with_suffix(target.suffix + ".tmp")
    with urlopen(url, timeout=60) as response, tmp.open("wb") as handle:  # noqa: S310
        handle.write(response.read())
    tmp.replace(target)


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
        description="Download pinned MITRE ATT&CK v19.1 STIX bundles."
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
