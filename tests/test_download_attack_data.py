"""Tests for attack_core.download — redirect security and STIX content validation.

All tests are network-free (monkeypatched or unit-testing internal helpers directly).
"""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

import pytest

from attack_core import download as download_attack_data
from attack_core.download import StrictRedirectHandler, _validate_stix_bundle


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _Response(BytesIO):
    """Minimal urllib response stand-in."""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class _FakeOpener:
    """Minimal urllib opener stand-in that wraps a _Response."""

    def __init__(self, response: _Response):
        self._response = response

    def open(self, url, timeout=None):
        return self._response


# ---------------------------------------------------------------------------
# Existing download behaviour
# ---------------------------------------------------------------------------


def test_download_streams_to_target(monkeypatch, tmp_path):
    monkeypatch.setattr(
        download_attack_data,
        "build_opener",
        lambda *_: _FakeOpener(_Response(b"official bundle bytes")),
    )
    target = tmp_path / "bundle.json"
    download_attack_data._download(
        "https://raw.githubusercontent.com/example/bundle", target
    )
    assert target.read_bytes() == b"official bundle bytes"
    assert not target.with_suffix(".json.tmp").exists()


def test_download_rejects_oversized_response_and_cleans_temp(monkeypatch, tmp_path):
    monkeypatch.setattr(
        download_attack_data,
        "build_opener",
        lambda *_: _FakeOpener(_Response(b"too large")),
    )
    target = tmp_path / "bundle.json"
    with pytest.raises(RuntimeError, match="oversized"):
        download_attack_data._download(
            "https://raw.githubusercontent.com/example/bundle", target, max_bytes=3
        )
    assert not target.exists()
    assert not target.with_suffix(".json.tmp").exists()


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/bundle.json",
        "http://raw.githubusercontent.com/example/bundle",
        "https://example.invalid/bundle",
    ],
)
def test_download_rejects_unapproved_urls(url, tmp_path):
    with pytest.raises(ValueError, match="approved download host"):
        download_attack_data._download(url, tmp_path / "bundle.json")


def test_v19_2_bundle_hashes_are_pinned():
    assert download_attack_data.ATTACK_STIX_TAG == "v19.2"
    assert download_attack_data.BUNDLES == {
        "enterprise-attack.json": {
            "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack.json",
            "sha256": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
        },
        "mobile-attack.json": {
            "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/mobile-attack/mobile-attack.json",
            "sha256": "acfa5ca2d93484476f79bf38590e2b55bb675fc0ce85e76bffa0af2c82dada64",
        },
        "ics-attack.json": {
            "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/ics-attack/ics-attack.json",
            "sha256": "08b83d2cea6b6d6752468ef0e62e2ab2a53c9443ef72c439ecccb07ab9e89da9",
        },
    }


# ---------------------------------------------------------------------------
# StrictRedirectHandler — redirect security unit tests
# ---------------------------------------------------------------------------


class TestStrictRedirectHandler:
    """Unit tests for StrictRedirectHandler._validate_redirect_url.

    Tests the redirect validation logic directly without network calls.
    """

    def test_redirect_to_attacker_domain_rejected(self):
        handler = StrictRedirectHandler()
        with pytest.raises(ValueError, match="not in the approved host list"):
            handler._validate_redirect_url("https://evil.com/attack.json")

    def test_http_downgrade_redirect_rejected(self):
        handler = StrictRedirectHandler()
        with pytest.raises(ValueError, match="only 'https' is allowed"):
            handler._validate_redirect_url(
                "http://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack.json"
            )

    def test_approved_https_redirect_allowed(self):
        """Redirect to another path on the same approved host must pass."""
        handler = StrictRedirectHandler()
        # Should not raise
        handler._validate_redirect_url(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack.json"
        )

    def test_ftp_scheme_redirect_rejected(self):
        handler = StrictRedirectHandler()
        with pytest.raises(ValueError, match="only 'https' is allowed"):
            handler._validate_redirect_url("ftp://raw.githubusercontent.com/evil.json")

    def test_file_scheme_redirect_rejected(self):
        handler = StrictRedirectHandler()
        with pytest.raises(ValueError, match="only 'https' is allowed"):
            handler._validate_redirect_url("file:///etc/passwd")

    @pytest.mark.parametrize(
        "bad_host",
        [
            "evil.com",
            "github.com",  # close but wrong subdomain
            "raw.githubusercontent.com.evil.com",  # subdomain spoofing
            "evil.raw.githubusercontent.com",  # prefix spoofing
            "raw.githubusercontent.com@evil.com",  # userinfo confusion
        ],
    )
    def test_various_attacker_domains_rejected(self, bad_host):
        handler = StrictRedirectHandler()
        with pytest.raises(ValueError, match="not in the approved host list"):
            handler._validate_redirect_url(f"https://{bad_host}/bundle.json")


# ---------------------------------------------------------------------------
# _validate_stix_bundle — content validation unit tests
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, data, filename="bundle.json") -> Path:
    p = tmp_path / filename
    if isinstance(data, dict):
        p.write_text(json.dumps(data), encoding="utf-8")
    else:
        p.write_bytes(data)
    return p


class TestValidateStixBundle:
    """Unit tests for _validate_stix_bundle.

    Proves that content validation catches all invalid shapes and does NOT
    delete a valid file on success.
    """

    def test_valid_stix_21_bundle_accepted(self, tmp_path):
        bundle = {
            "type": "bundle",
            "id": "bundle--1234",
            "spec_version": "2.1",
            "objects": [{"type": "attack-pattern", "id": "attack-pattern--1234"}],
        }
        p = _write(tmp_path, bundle)
        _validate_stix_bundle(p)  # must not raise
        assert p.exists()  # file must NOT be deleted on success

    def test_valid_stix_20_bundle_accepted(self, tmp_path):
        bundle = {
            "type": "bundle",
            "spec_version": "2.0",
            "objects": [{"type": "attack-pattern"}],
        }
        p = _write(tmp_path, bundle)
        _validate_stix_bundle(p)

    def test_valid_bundle_with_object_spec_version_accepted(self, tmp_path):
        bundle = {
            "type": "bundle",
            "id": "bundle--1234",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1234",
                    "spec_version": "2.1",
                }
            ],
        }
        p = _write(tmp_path, bundle)
        _validate_stix_bundle(p)
        assert p.exists()

    def test_invalid_json_rejected_and_deleted(self, tmp_path):
        p = _write(tmp_path, b"this is not json at all {{{{")
        with pytest.raises(ValueError, match="not valid UTF-8 JSON"):
            _validate_stix_bundle(p)
        assert not p.exists(), "Invalid-JSON file must be deleted on failure"

    def test_wrong_type_rejected_and_deleted(self, tmp_path):
        bundle = {"type": "attack-pattern", "spec_version": "2.1", "objects": [{}]}
        p = _write(tmp_path, bundle)
        with pytest.raises(ValueError, match="Expected STIX bundle type"):
            _validate_stix_bundle(p)
        assert not p.exists()

    def test_missing_type_field_rejected_and_deleted(self, tmp_path):
        bundle = {"spec_version": "2.1", "objects": [{"type": "attack-pattern"}]}
        p = _write(tmp_path, bundle)
        with pytest.raises(ValueError, match="Expected STIX bundle type"):
            _validate_stix_bundle(p)
        assert not p.exists()

    def test_stix_1x_spec_version_rejected_and_deleted(self, tmp_path):
        bundle = {"type": "bundle", "spec_version": "1.2", "objects": [{}]}
        p = _write(tmp_path, bundle)
        with pytest.raises(ValueError, match="spec_version"):
            _validate_stix_bundle(p)
        assert not p.exists()

    def test_empty_objects_list_rejected_and_deleted(self, tmp_path):
        bundle = {"type": "bundle", "spec_version": "2.1", "objects": []}
        p = _write(tmp_path, bundle)
        with pytest.raises(ValueError, match="empty"):
            _validate_stix_bundle(p)
        assert not p.exists()

    def test_missing_objects_field_rejected_and_deleted(self, tmp_path):
        bundle = {"type": "bundle", "spec_version": "2.1"}
        p = _write(tmp_path, bundle)
        with pytest.raises(ValueError, match="empty"):
            _validate_stix_bundle(p)
        assert not p.exists()

    def test_json_array_at_root_rejected_and_deleted(self, tmp_path):
        p = _write(tmp_path, b'[{"type": "bundle"}]')
        with pytest.raises(ValueError, match="JSON object"):
            _validate_stix_bundle(p)
        assert not p.exists()

    def test_spec_version_21_prefix_matched(self, tmp_path):
        """spec_version '2.1.0' (hypothetical) should be accepted (starts with '2.')."""
        bundle = {
            "type": "bundle",
            "spec_version": "2.1.0",
            "objects": [{"type": "attack-pattern"}],
        }
        p = _write(tmp_path, bundle)
        _validate_stix_bundle(p)
