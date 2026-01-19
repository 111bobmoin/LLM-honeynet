#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from orchestrator import TrapAgent, TrapAgentConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Trap Agent pipeline runner")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["host", "interhost", "all"],
        default="all",
        help="Pipeline stage to execute (default: all)",
    )
    parser.add_argument(
        "--short-memory",
        type=Path,
        default=Path("shadow/honey_agent.json"),
        help="Short-term memory JSON path produced by Honey Agent",
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
        default=0.15,
        help="OpenAI decoding temperature",
    )
    parser.add_argument(
        "--openai-top-p",
        type=float,
        default=0.85,
        help="OpenAI top_p nucleus sampling parameter",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the aggregated JSON output (default: stdout only)",
    )
    return parser.parse_args()


def execute(agent: TrapAgent, mode: str) -> Dict[str, Any]:
    if mode == "host":
        return agent.run_host_trap_chain()
    if mode == "interhost":
        return agent.run_interhost_trap_chain()
    return agent.run_full_pipeline()


def main() -> None:
    args = parse_args()
    config = TrapAgentConfig(
        short_memory_path=args.short_memory,
        preferences_path=args.preferences,
        openai_key_path=args.openai_key,
        openai_model=args.openai_model,
        openai_temperature=args.openai_temperature,
        openai_top_p=args.openai_top_p,
    )
    agent = TrapAgent(config)
    payload = execute(agent, args.mode)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[+] Trap Agent {args.mode} output saved to {args.output}")
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
