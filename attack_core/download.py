"""Deprecated compatibility wrapper for attack_v19_core.download."""

from attack_v19_core.download import (
    ALLOWED_DOWNLOAD_HOSTS,
    ATTACK_STIX_TAG,
    BASE_URL,
    BUNDLES,
    MAX_BUNDLE_BYTES,
    StrictRedirectHandler,
    _download,
    _sha256,
    _validate_stix_bundle,
    ensure_attack_data,
    main,
)

__all__ = [
    "ALLOWED_DOWNLOAD_HOSTS",
    "ATTACK_STIX_TAG",
    "BASE_URL",
    "BUNDLES",
    "MAX_BUNDLE_BYTES",
    "StrictRedirectHandler",
    "ensure_attack_data",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
