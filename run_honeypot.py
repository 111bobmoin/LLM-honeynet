#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from honeypot import HoneypotRuntime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Configurable multi-service honeypot")
    parser.add_argument(
        "--config-dir",
        default="config",
        type=Path,
        help="Directory containing *_config.json files",
    )
    parser.add_argument(
        "--deployment",
        help="Deployment host to run from deployments/<host>/config",
    )
    parser.add_argument(
        "--deployments-root",
        default="deployments",
        type=Path,
        help="Root directory containing generated deployment configs",
    )
    parser.add_argument(
        "--services",
        default="auto",
        help="Comma-separated services to enable (ssh,telnet,ftp,http,https,mysql,postgresql,rdp) or 'auto' to load all available configs",
    )
    return parser.parse_args()


def parse_services_argument(value: str):
    if not value or value.lower() == "auto":
        return None
    selected = [item.strip() for item in value.split(",") if item.strip()]
    return selected or None


def resolve_config_dir(args: argparse.Namespace) -> Path:
    if args.deployment:
        return args.deployments_root / args.deployment / "config"
    return args.config_dir


async def main_async(args: argparse.Namespace) -> None:
    services = parse_services_argument(args.services)
    config_dir = resolve_config_dir(args)
    runtime = HoneypotRuntime(config_dir, services=services)
    runtime.load_services()
    if not runtime.services:
        raise RuntimeError(f"No services loaded from {config_dir}. Provide configs or specify --services.")
    await runtime.start()


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
