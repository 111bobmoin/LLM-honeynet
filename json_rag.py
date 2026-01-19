#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is on sys.path when launched directly.
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from orchestrator.rag import cli_main  # noqa: E402


def main() -> int:
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())

