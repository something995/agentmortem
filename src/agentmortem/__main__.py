"""Allow ``python -m agentmortem``."""

from __future__ import annotations

import sys

from agentmortem.cli import main

if __name__ == "__main__":
    sys.exit(main())
