"""Allow running as: python -m attack_core <command>"""

import sys

from .cli import main

sys.exit(main())
