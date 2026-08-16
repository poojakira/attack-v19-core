from __future__ import annotations

import re
import sys
import types
from functools import total_ordering


@total_ordering
class StrictVersion:
    def __init__(self, vstring: object):
        self.vstring = str(vstring)
        self.version = tuple(int(part) for part in re.findall(r"\d+", self.vstring))

    def __str__(self) -> str:
        return self.vstring

    def __repr__(self) -> str:
        return f"StrictVersion({self.vstring!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StrictVersion):
            other = StrictVersion(other)
        return self.version == other.version

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, StrictVersion):
            other = StrictVersion(other)
        return self.version < other.version


def ensure_distutils_version() -> None:
    try:
        __import__("distutils.version")
        return
    except ModuleNotFoundError:
        pass

    distutils_module = types.ModuleType("distutils")
    version_module = types.ModuleType("distutils.version")
    setattr(version_module, "StrictVersion", StrictVersion)
    setattr(distutils_module, "version", version_module)
    sys.modules.setdefault("distutils", distutils_module)
    sys.modules.setdefault("distutils.version", version_module)
