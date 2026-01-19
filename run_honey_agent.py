#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional

from orchestrator import HoneyAgent, HoneyAgentConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Honey Agent pipeline runner")
    parser.add_argument(
        "--mode",
        choices=["initialization", "finetune"],
        default="initialization",
        help="Which pipeline to execute (default: initialization)",
    )
    parser.add_argument(
        "--short-memory",
        type=Path,
        default=Path("shadow/honey_agent.json"),
        help="Short-term memory JSON path (host -> port -> file -> vulnerability tree)",
    )
    parser.add_argument(
        "--long-memory",
        type=Path,
        default=Path("shadow/long_memory.json"),
        help="Long-term memory JSON path (shared facts by node identity)",
    )
    parser.add_argument(
        "--topology",
        type=Path,
        default=Path("shadow/shadow_topology.json"),
        help="Shadow topology JSON path",
    )
    parser.add_argument(
        "--topology-fallback",
        type=Path,
        default=Path("enterprise/enterprise_topology.json"),
        help="Fallback topology JSON path when shadow topology is missing",
    )
    parser.add_argument(
        "--preferences",
        type=Path,
        default=Path("shadow/attacker_preferences.json"),
        help="File containing attacker preference strings (JSON list)",
    )
    parser.add_argument(
        "--openai-key",
        type=Path,
        default=Path("secrets/openai_api_key.txt"),
        help="OpenAI API key file path",
    )
    parser.add_argument(
        "--openai-model",
        default="gpt-4o-mini",
        help="OpenAI model name (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--openai-temperature",
        type=float,
        default=0.1,
        help="OpenAI decoding temperature",
    )
    parser.add_argument(
        "--openai-top-p",
        type=float,
        default=0.9,
        help="OpenAI top_p nucleus sampling parameter",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the aggregated JSON output (default: stdout only)",
    )
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> HoneyAgentConfig:
    return HoneyAgentConfig(
        short_memory_path=args.short_memory,
        long_memory_path=args.long_memory,
        topology_path=args.topology,
        fallback_topology_path=args.topology_fallback,
        preferences_path=args.preferences,
        openai_key_path=args.openai_key,
        openai_model=args.openai_model,
        openai_temperature=args.openai_temperature,
        openai_top_p=args.openai_top_p,
    )


def run_pipeline(agent: HoneyAgent, mode: str) -> Dict[str, Any]:
    if mode == "initialization":
        return agent.run_initialization()
    return agent.run_finetune()


def main() -> None:
    args = parse_args()
    config = build_config(args)
    agent = HoneyAgent(config)
    payload = run_pipeline(agent, args.mode)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[+] Honey Agent {args.mode} output saved to {args.output}")
    else:
        print(f"[+] Honey Agent {args.mode} completed and saved to {config.short_memory_path}")


if __name__ == "__main__":
    main()
