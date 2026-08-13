import argparse

from attack_core.cli import cmd_revoked


def test_revoked_command_separates_release_and_legacy_maps(capsys):
    assert cmd_revoked(argparse.Namespace()) == 0

    output = capsys.readouterr().out
    assert "Official ATT&CK v19 technique revocations (22 entries)" in output
    assert "Older compatibility aliases (7 entries)" in output
    assert "(self)" not in output
