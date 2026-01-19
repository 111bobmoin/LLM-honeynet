#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from orchestrator.topology import build_shadow_topology, load_enterprise_topology, write_shadow_artifacts  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build shadow topology from enterprise topology without mem0.")
    parser.add_argument(
        "--enterprise",
        type=Path,
        default=Path("enterprise"),
        help="Directory containing enterprise_topology.json (default: enterprise/)",
    )
    parser.add_argument(
        "--shadow-dir",
        type=Path,
        default=Path("shadow"),
        help="Output directory for shadow topology artifacts (default: shadow/)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    topo = load_enterprise_topology(args.enterprise)
    shadow = build_shadow_topology(topo)
    topo_path, mininet_path = write_shadow_artifacts(shadow, args.shadow_dir)
    print(f"[+] Shadow topology written to {topo_path}")
    print(f"[+] Mininet script written to {mininet_path}")


if __name__ == "__main__":
    main()
