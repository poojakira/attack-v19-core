"""Deprecated compatibility wrapper for attack_v19_core.cli."""

from attack_v19_core.cli import (
    _build_parser,
    _load_index,
    cmd_lookup,
    cmd_navigator,
    cmd_revoked,
    main,
)

__all__ = ["cmd_lookup", "cmd_navigator", "cmd_revoked", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
