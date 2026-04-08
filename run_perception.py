#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from orchestrator.topology import build_shadow_topology, load_enterprise_topology, update_rag_cache, write_shadow_artifacts
from perception import HostAnalysis, OpenAISummarizer, analyze_host, load_rules


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Perception pipeline for honeynet logs.")
    parser.add_argument(
        "--hosts",
        help="Comma-separated host identifiers (matching deployments/<host>/logs). If omitted, auto-discover.",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        help="Optional additional perception rule overrides applied after config-derived rules.",
    )
    parser.add_argument(
        "--base-config",
        type=Path,
        default=Path("config"),
        help="Fallback config directory when host-specific config is missing.",
    )
    parser.add_argument(
        "--include-base",
        action="store_true",
        help="Include shared logs/ directory as host 'base'.",
    )
    parser.add_argument(
        "--openai",
        action="store_true",
        help="Call OpenAI API for preference summarisation (requires secrets/openai_api_key.txt).",
    )
    parser.add_argument(
        "--openai-model",
        default="gpt-5.4-mini",
        help="OpenAI model name for preference summarisation (default: gpt-5.4-mini)",
    )
    parser.add_argument(
        "--preferences-output",
        type=Path,
        default=Path("shadow/attacker_preferences.json"),
        help="Path to write extracted attacker preferences when using --openai (default: shadow/attacker_preferences.json)",
    )
    parser.add_argument(
        "--enterprise-dir",
        type=Path,
        default=Path("enterprise"),
        help="Directory containing enterprise_topology.json used to derive the shadow topology.",
    )
    parser.add_argument(
        "--shadow-dir",
        type=Path,
        default=Path("shadow"),
        help="Directory used to store shadow topology artifacts.",
    )
    parser.add_argument(
        "--skip-shadow-topology",
        action="store_true",
        help="Skip generating shadow_topology.json and mininet_shadow.py artifacts.",
    )
    return parser.parse_args()


def discover_hosts(include_base: bool) -> Dict[str, Path]:
    hosts: Dict[str, Path] = {}
    if include_base and Path("logs").exists():
        hosts["base"] = Path("logs")
    deploy_root = Path("deployments")
    if deploy_root.exists():
        for host_dir in sorted(p for p in deploy_root.iterdir() if p.is_dir()):
            log_dir = host_dir / "logs"
            if log_dir.exists():
                hosts[host_dir.name] = log_dir
    # Backward compatibility with legacy layout (logs_hostname)
    for path in sorted(Path(".").glob("logs_*")):
        host = path.name.split("_", 1)[1] if "_" in path.name else path.name
        hosts.setdefault(host, path)
    return hosts


def select_hosts(hosts_arg: str, discovered: Dict[str, Path]) -> Dict[str, Path]:
    if not hosts_arg:
        return discovered
    selected: Dict[str, Path] = {}
    for host in [token.strip() for token in hosts_arg.split(",") if token.strip()]:
        if host not in discovered:
            raise ValueError(f"Host '{host}' not found. Available: {', '.join(discovered)}")
        selected[host] = discovered[host]
    return selected


def print_analysis(analysis: HostAnalysis) -> None:
    print(f"[{analysis.host}] max stage -> {analysis.stage_label()}")
    for event in analysis.events:
        if not event.stage:
            continue
        print(f"  - {event.timestamp.isoformat()} :: {event.stage} :: {event.summary()}")


def extract_preferences(summary: str) -> List[str]:
    """Heuristically extract bullet-style preferences from a freeform summary."""
    preferences: List[str] = []
    for line in summary.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Trim common bullet markers and leading numbers.
        while stripped[:1] in {"-", "*", "•"} or stripped[:1].isdigit():
            stripped = stripped[1:].lstrip(" .)")
        stripped = stripped.strip()
        if stripped:
            preferences.append(stripped)
    if not preferences and summary.strip():
        preferences.append(summary.strip())
    return preferences


def save_preferences(preferences: List[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(preferences, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def generate_shadow_topology(enterprise_dir: Path, shadow_dir: Path) -> tuple[Path, Path]:
    enterprise_topology = load_enterprise_topology(enterprise_dir)
    shadow_topology = build_shadow_topology(enterprise_topology)
    topology_path, mininet_path = write_shadow_artifacts(shadow_topology, shadow_dir)
    update_rag_cache(shadow_topology, source=f"enterprise:{enterprise_dir / 'enterprise_topology.json'}")
    return topology_path, mininet_path


def main() -> None:
    args = parse_args()

    discovered = discover_hosts(include_base=args.include_base)
    selected = select_hosts(args.hosts, discovered)

    if not selected:
        print("No hosts found. Ensure log directories exist (e.g., deployments/h1/logs).")
        return

    analyses: List[HostAnalysis] = []
    for host, log_dir in selected.items():
        if not log_dir.exists():
            print(f"[!] Log directory missing for host '{host}': {log_dir}")
            continue
        config_dir = (log_dir.parent / "config").resolve()
        if not config_dir.exists():
            config_dir = args.base_config.resolve()
        rules = load_rules(config_dir, external_rules=args.rules)
        analysis = analyze_host(host, log_dir, rules)
        analyses.append(analysis)
        print_analysis(analysis)

    if args.openai and analyses:
        summarizer = OpenAISummarizer(model=args.openai_model)
        summary = summarizer.summarize(analyses)
        print("\n[OpenAI Preference Summary]")
        print(summary)
        preferences = extract_preferences(summary)
        save_preferences(preferences, args.preferences_output)
        print("\n[Attacker Preferences]")
        print(f"Saved {len(preferences)} preference(s) to {args.preferences_output}")

    if not args.skip_shadow_topology:
        topology_path, mininet_path = generate_shadow_topology(
            enterprise_dir=args.enterprise_dir.resolve(),
            shadow_dir=args.shadow_dir.resolve(),
        )
        print("\n[Shadow Topology]")
        print(f"Saved topology to {topology_path}")
        print(f"Saved Mininet launcher to {mininet_path}")


if __name__ == "__main__":
    main()
