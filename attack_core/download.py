from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener, urlopen  # noqa: F401 – urlopen kept for monkeypatching in tests

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


class StrictRedirectHandler(HTTPRedirectHandler):
    """Intercept every HTTP redirect and reject any that leave the allowed host list.

    urllib's default redirect handler follows 301/302 without re-validating the
    target URL.  This handler validates that every redirect target:
      - uses the ``https`` scheme (no downgrade to plain HTTP), and
      - has a hostname present in ``ALLOWED_DOWNLOAD_HOSTS``.

    Raises ``ValueError`` immediately if either condition is not met, aborting
    the request before the redirect is followed.
    """

    def _validate_redirect_url(self, newurl: str) -> None:
        parsed = urlsplit(newurl)
        if parsed.scheme != "https":
            raise ValueError(
                f"Redirect target uses scheme {parsed.scheme!r}; only 'https' is allowed"
            )
        if parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise ValueError(
                f"Redirect target hostname {parsed.hostname!r} is not in the approved host list"
            )

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        self._validate_redirect_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_301(self, req, fp, code, msg, headers):  # type: ignore[override]
        newurl = headers.get("Location", "")
        self._validate_redirect_url(newurl)
        return super().http_error_301(req, fp, code, msg, headers)

    def http_error_302(self, req, fp, code, msg, headers):  # type: ignore[override]
        newurl = headers.get("Location", "")
        self._validate_redirect_url(newurl)
        return super().http_error_302(req, fp, code, msg, headers)

    def http_error_303(self, req, fp, code, msg, headers):  # type: ignore[override]
        newurl = headers.get("Location", "")
        self._validate_redirect_url(newurl)
        return super().http_error_303(req, fp, code, msg, headers)

    def http_error_307(self, req, fp, code, msg, headers):  # type: ignore[override]
        newurl = headers.get("Location", "")
        self._validate_redirect_url(newurl)
        return super().http_error_307(req, fp, code, msg, headers)

    def http_error_308(self, req, fp, code, msg, headers):  # type: ignore[override]
        newurl = headers.get("Location", "")
        self._validate_redirect_url(newurl)
        return super().http_error_308(req, fp, code, msg, headers)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_stix_bundle(path: Path) -> None:
    """Validate a downloaded file is a well-formed STIX 2.x ATT&CK bundle.

    Called AFTER SHA-256 verification passes. A hash-matching file that is not
    a valid STIX bundle (e.g. an attacker-substituted JSON with a matching hash
    via a prefix-collision or supply-chain attack) is rejected here.

    Checks:
    1. File is valid UTF-8 JSON (raises ValueError on parse failure).
    2. Top-level ``type`` field equals ``"bundle"`` (STIX 2.x bundle type).
    3. ``objects`` is a non-empty list (an empty bundle has no ATT&CK content).
    4. Root or contained objects declare ``spec_version`` starting with ``"2."``
       (STIX 2.x; not STIX 1.x).

    On failure the file is unlinked and ValueError is raised so the caller
    can treat it as a failed download.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        path.unlink(missing_ok=True)
        raise ValueError(f"Downloaded bundle is not valid UTF-8 JSON: {exc}") from exc
    except OSError as exc:
        raise ValueError(
            f"Cannot read downloaded bundle for validation: {exc}"
        ) from exc

    if not isinstance(data, dict):
        path.unlink(missing_ok=True)
        raise ValueError(
            f"STIX bundle root must be a JSON object; got {type(data).__name__}"
        )
    bundle_type = data.get("type")
    if bundle_type != "bundle":
        path.unlink(missing_ok=True)
        raise ValueError(
            f"Expected STIX bundle type 'bundle'; got {bundle_type!r}. "
            "This file does not appear to be an ATT&CK STIX bundle."
        )
    objects = data.get("objects")
    if not isinstance(objects, list) or len(objects) == 0:
        path.unlink(missing_ok=True)
        raise ValueError(
            "STIX bundle 'objects' is empty or missing  --  bundle has no ATT&CK content."
        )
    root_spec_version = str(data.get("spec_version", ""))
    object_spec_versions = [
        str(obj.get("spec_version", "")) for obj in objects if isinstance(obj, dict)
    ]
    has_stix_2_version = root_spec_version.startswith("2.") or any(
        version.startswith("2.") for version in object_spec_versions
    )
    if not has_stix_2_version:
        path.unlink(missing_ok=True)
        observed = root_spec_version or ", ".join(
            version for version in object_spec_versions if version
        )
        raise ValueError(
            "Expected STIX 2.x spec_version (e.g. '2.0' or '2.1') on the "
            f"bundle root or contained objects; got {observed!r}."
        )


def _download(url: str, target: Path, *, max_bytes: int = MAX_BUNDLE_BYTES) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError("Bundle URL must use HTTPS on an approved download host")
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    opener = build_opener(StrictRedirectHandler())
    try:
        # The scheme and host are allowlisted immediately above.
        # StrictRedirectHandler validates every redirect target before following.
        with opener.open(url, timeout=60) as response, tmp.open("wb") as handle:  # nosec B310
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
        # Content validation: verify the file is a well-formed STIX 2.x ATT&CK bundle
        # before it takes the place of any previously trusted data.
        _validate_stix_bundle(target)
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
