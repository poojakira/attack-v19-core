import warnings


def test_attack_core_shim_emits_deprecation_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        import importlib
        import sys

        # Remove cached import to force re-import and trigger warning
        sys.modules.pop("attack_core", None)
        importlib.import_module("attack_core")
    assert any(issubclass(warning.category, DeprecationWarning) for warning in w)
    assert any("attack_v19_core" in str(warning.message) for warning in w)
