#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full honeynet pipeline end-to-end.")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Project root directory.",
    )
    parser.add_argument(
        "--openai",
        action="store_true",
        help="Use OpenAI during perception preference summarisation.",
    )
    parser.add_argument(
        "--honey-mode",
        choices=["initialization", "finetune"],
        default="initialization",
        help="Honey Agent mode.",
    )
    parser.add_argument(
        "--trap-mode",
        choices=["host", "interhost", "all"],
        default="all",
        help="Trap Agent mode.",
    )
    parser.add_argument(
        "--deception-mode",
        choices=["consistency", "generate-configs", "full"],
        default="full",
        help="Deception stage mode.",
    )
    parser.add_argument(
        "--skip-network",
        action="store_true",
        help="Skip launching the Mininet shadow network.",
    )
    parser.add_argument(
        "--network-no-cli",
        action="store_true",
        help="Launch Mininet without entering the CLI.",
    )
    parser.add_argument(
        "--network-duration",
        type=float,
        default=0.0,
        help="When used with --network-no-cli, keep the network alive for N seconds before stopping.",
    )
    return parser.parse_args()


def run_step(project_root: Path, description: str, command: list[str]) -> None:
    print(f"\n=== {description} ===")
    print(" ".join(command))
    subprocess.run(command, cwd=project_root, check=True)


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve()

    perception_command = ["python3", "run_perception.py"]
    if args.openai:
        perception_command.append("--openai")
    run_step(project_root, "Perception", perception_command)

    run_step(
        project_root,
        "Honey Agent",
        ["python3", "run_honey_agent.py", "--mode", args.honey_mode],
    )

    run_step(
        project_root,
        "Trap Agent",
        ["python3", "run_trap_agent.py", args.trap_mode],
    )

    run_step(
        project_root,
        "Deception",
        ["python3", "run_deception.py", "--mode", args.deception_mode],
    )

    if not args.skip_network:
        network_command = [
            "python3",
            "shadow/mininet_shadow.py",
            "--topology",
            "shadow/shadow_topology.json",
            "--start-honeypots",
            "--project-root",
            str(project_root),
        ]
        if args.network_no_cli:
            network_command.append("--no-cli")
        if args.network_duration > 0:
            network_command.extend(["--duration", str(args.network_duration)])
        run_step(project_root, "Shadow Network", network_command)


if __name__ == "__main__":
    main()
