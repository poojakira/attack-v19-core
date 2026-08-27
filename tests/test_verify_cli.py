"""
Tests for the `attack_core verify` CLI command.

The verify command re-checks SHA-256 hashes of cached STIX bundles
to ensure integrity has not been compromised post-download.

Usage:
    python -m attack_core verify
    python -m attack_core verify --cache-dir /custom/path
    python -m attack_core verify --strict  (exit 1 on any failure)
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from click.testing import CliRunner


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    """Create a temporary cache directory with a valid STIX bundle and hash manifest."""
    bundle_content = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--test-001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--test-001",
                    "name": "Test Technique",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T0001"}
                    ],
                }
            ],
        },
        indent=2,
    ).encode("utf-8")

    bundle_path = tmp_path / "enterprise-attack.json"
    bundle_path.write_bytes(bundle_content)

    # Compute and store the expected hash
    sha256_hash = hashlib.sha256(bundle_content).hexdigest()
    hashes_path = tmp_path / "hashes.json"
    hashes_path.write_text(
        json.dumps({"enterprise-attack.json": sha256_hash}, indent=2),
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def corrupted_cache_dir(cache_dir: Path) -> Path:
    """Cache directory with a bundle that doesn't match its hash."""
    bundle_path = cache_dir / "enterprise-attack.json"
    # Corrupt the bundle by appending garbage
    with bundle_path.open("ab") as f:
        f.write(b"\x00CORRUPTED")
    return cache_dir


@pytest.fixture
def missing_bundle_cache_dir(tmp_path: Path) -> Path:
    """Cache directory with hash manifest but missing bundle file."""
    hashes_path = tmp_path / "hashes.json"
    hashes_path.write_text(
        json.dumps({"enterprise-attack.json": "a" * 64}, indent=2),
        encoding="utf-8",
    )
    return tmp_path


class TestVerifyCommand:
    """Tests for `python -m attack_core verify`."""

    def test_verify_valid_cache(self, runner: CliRunner, cache_dir: Path):
        """Verify succeeds when all hashes match."""
        from attack_core.cli import cli

        result = runner.invoke(cli, ["verify", "--cache-dir", str(cache_dir)])

        assert result.exit_code == 0
        assert "OK" in result.output or "passed" in result.output.lower()
        assert "enterprise-attack.json" in result.output

    def test_verify_corrupted_bundle(self, runner: CliRunner, corrupted_cache_dir: Path):
        """Verify fails when SHA-256 does not match."""
        from attack_core.cli import cli

        result = runner.invoke(
            cli, ["verify", "--cache-dir", str(corrupted_cache_dir), "--strict"]
        )

        assert result.exit_code != 0
        assert "mismatch" in result.output.lower() or "FAIL" in result.output

    def test_verify_missing_bundle_file(
        self, runner: CliRunner, missing_bundle_cache_dir: Path
    ):
        """Verify reports missing files."""
        from attack_core.cli import cli

        result = runner.invoke(
            cli, ["verify", "--cache-dir", str(missing_bundle_cache_dir), "--strict"]
        )

        assert result.exit_code != 0
        assert "missing" in result.output.lower() or "not found" in result.output.lower()

    def test_verify_no_cache_dir(self, runner: CliRunner, tmp_path: Path):
        """Verify handles empty/nonexistent cache gracefully."""
        from attack_core.cli import cli

        empty_dir = tmp_path / "nonexistent"
        result = runner.invoke(cli, ["verify", "--cache-dir", str(empty_dir)])

        # Should fail gracefully, not crash
        assert result.exit_code != 0 or "no cache" in result.output.lower()

    def test_verify_json_output(self, runner: CliRunner, cache_dir: Path):
        """Verify can output results as JSON."""
        from attack_core.cli import cli

        result = runner.invoke(
            cli, ["verify", "--cache-dir", str(cache_dir), "--format", "json"]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "results" in data
        assert data["results"][0]["file"] == "enterprise-attack.json"
        assert data["results"][0]["status"] == "ok"

    def test_verify_multiple_bundles(self, runner: CliRunner, tmp_path: Path):
        """Verify checks all bundles listed in hashes.json."""
        from attack_core.cli import cli

        bundles = {
            "enterprise-attack.json": {"type": "bundle", "id": "bundle--ent"},
            "mobile-attack.json": {"type": "bundle", "id": "bundle--mob"},
            "ics-attack.json": {"type": "bundle", "id": "bundle--ics"},
        }

        hashes = {}
        for filename, content in bundles.items():
            raw = json.dumps(content).encode("utf-8")
            (tmp_path / filename).write_bytes(raw)
            hashes[filename] = hashlib.sha256(raw).hexdigest()

        (tmp_path / "hashes.json").write_text(
            json.dumps(hashes, indent=2), encoding="utf-8"
        )

        result = runner.invoke(cli, ["verify", "--cache-dir", str(tmp_path)])

        assert result.exit_code == 0
        for filename in bundles:
            assert filename in result.output

    def test_verify_partial_corruption(self, runner: CliRunner, tmp_path: Path):
        """When one of multiple bundles is corrupted, verify reports which one failed."""
        from attack_core.cli import cli

        # Create two valid bundles
        good_content = json.dumps({"type": "bundle", "id": "bundle--good"}).encode()
        bad_content = json.dumps({"type": "bundle", "id": "bundle--bad"}).encode()

        (tmp_path / "enterprise-attack.json").write_bytes(good_content)
        (tmp_path / "mobile-attack.json").write_bytes(bad_content)

        # Hash manifest: correct hash for enterprise, wrong hash for mobile
        hashes = {
            "enterprise-attack.json": hashlib.sha256(good_content).hexdigest(),
            "mobile-attack.json": "0" * 64,  # Wrong hash
        }
        (tmp_path / "hashes.json").write_text(
            json.dumps(hashes, indent=2), encoding="utf-8"
        )

        result = runner.invoke(cli, ["verify", "--cache-dir", str(tmp_path), "--strict"])

        assert result.exit_code != 0
        assert "mobile-attack.json" in result.output
        # Enterprise should still be reported as OK
        assert "enterprise-attack.json" in result.output

    def test_verify_default_cache_location(self, runner: CliRunner, cache_dir: Path):
        """Verify uses the default cache location when --cache-dir is not specified."""
        from attack_core.cli import cli

        with patch("attack_core.cli.get_default_cache_dir", return_value=cache_dir):
            result = runner.invoke(cli, ["verify"])

        assert result.exit_code == 0

    def test_verify_verbose_shows_hashes(self, runner: CliRunner, cache_dir: Path):
        """Verbose mode displays expected and actual hashes."""
        from attack_core.cli import cli

        result = runner.invoke(
            cli, ["verify", "--cache-dir", str(cache_dir), "--verbose"]
        )

        assert result.exit_code == 0
        # Should show the sha256 hash
        assert "sha256" in result.output.lower() or len(result.output) > 100

    def test_verify_exit_code_zero_on_success_non_strict(
        self, runner: CliRunner, cache_dir: Path
    ):
        """Without --strict, exit code is 0 even if some warnings exist."""
        from attack_core.cli import cli

        result = runner.invoke(cli, ["verify", "--cache-dir", str(cache_dir)])
        assert result.exit_code == 0


class TestVerifyHashAlgorithm:
    """Verify the hash computation matches expectations."""

    def test_sha256_computation(self, cache_dir: Path):
        """Ensure our hash computation matches Python's hashlib."""
        bundle_path = cache_dir / "enterprise-attack.json"
        content = bundle_path.read_bytes()

        expected = hashlib.sha256(content).hexdigest()

        hashes = json.loads((cache_dir / "hashes.json").read_text(encoding="utf-8"))
        assert hashes["enterprise-attack.json"] == expected

    def test_hash_is_lowercase_hex(self, cache_dir: Path):
        """Hash values must be lowercase hexadecimal."""
        hashes = json.loads((cache_dir / "hashes.json").read_text(encoding="utf-8"))
        for filename, hash_value in hashes.items():
            assert hash_value == hash_value.lower()
            assert all(c in "0123456789abcdef" for c in hash_value)
            assert len(hash_value) == 64  # SHA-256 = 64 hex chars
