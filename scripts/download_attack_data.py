"""Source-checkout wrapper for ``python -m attack_core.download``."""

from attack_core.download import main


if __name__ == "__main__":
    raise SystemExit(main())
