#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from deception import DeceptionAgent, DeceptionAgentConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deception agent pipeline runner")
    parser.add_argument(
        "--mode",
        choices=["consistency", "generate-configs", "full"],
        default="full",
        help="Pipeline stage to execute (default: full)",
    )
    parser.add_argument(
        "--hosts",
        help="Comma-separated host names to limit config generation (default: all deployments)",
    )
    parser.add_argument(
        "--deploy-root",
        type=Path,
        default=Path("deployments"),
        help="Deployments root directory (default: deployments/)",
    )
    parser.add_argument(
        "--short-memory",
        type=Path,
        default=Path("shadow/honey_agent.json"),
        help="Short-term memory JSON path (host tree from Honey/Trap agents)",
    )
    parser.add_argument(
        "--long-memory",
        type=Path,
        default=Path("shadow/long_memory.json"),
        help="Long-term memory JSON path (shared factual hints)",
    )
    parser.add_argument(
        "--trap-memory",
        type=Path,
        default=Path("shadow/trap_agent.json"),
        help="Trap memory JSON path (host loops + interhost chains)",
    )
    parser.add_argument(
        "--base-config",
        type=Path,
        default=Path("config"),
        help="Fallback base config directory (default: config/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write combined JSON output (default: stdout only)",
    )
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> DeceptionAgentConfig:
    return DeceptionAgentConfig(
        deployments_root=args.deploy_root,
        base_config_dir=args.base_config,
        short_memory_path=args.short_memory,
        long_memory_path=args.long_memory,
        trap_memory_path=args.trap_memory,
    )


def run_pipeline(agent: DeceptionAgent, mode: str, hosts: Optional[Iterable[str]]) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    if mode in {"consistency", "full"}:
        results["consistency_report"] = agent.run_consistency_check(save=True)
    if mode in {"generate-configs", "full"}:
        results["host_configs"] = agent.generate_host_configs(hosts=hosts)
    return results


def main() -> None:
    args = parse_args()
    host_set = [token.strip() for token in args.hosts.split(",")] if args.hosts else None
    config = build_config(args)
    agent = DeceptionAgent(config)
    payload = run_pipeline(agent, args.mode, host_set)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[+] Deception {args.mode} output saved to {args.output}")
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
