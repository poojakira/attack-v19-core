from io import BytesIO

import pytest

from attack_core import download as download_attack_data


class Response(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_download_streams_to_target(monkeypatch, tmp_path):
    monkeypatch.setattr(
        download_attack_data,
        "urlopen",
        lambda _url, timeout: Response(b"official bundle bytes"),
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
        "urlopen",
        lambda _url, timeout: Response(b"too large"),
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
