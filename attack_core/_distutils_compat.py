from __future__ import annotations

import sys
import types

from packaging.version import Version


def ensure_distutils_version() -> None:
    try:
        import distutils.version  # noqa: F401

        return
    except ModuleNotFoundError:
        pass

    distutils_module = types.ModuleType("distutils")
    version_module = types.ModuleType("distutils.version")
    version_module.StrictVersion = Version
    distutils_module.version = version_module
    sys.modules.setdefault("distutils", distutils_module)
    sys.modules.setdefault("distutils.version", version_module)
