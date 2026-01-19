#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import sys
import json
from pathlib import Path

BASE_CONFIG_DIR = Path("config")
BASE_RUNNER = Path("run_honeypot.py")
DEPLOY_ROOT = Path("deployments")
STATIC_DIRS = [Path("www"), Path("ftp")]


def sanitize(name: str) -> str:
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in ("_", "-"))
    if not cleaned:
        raise ValueError("Host name must contain alphanumeric characters.")
    return cleaned


def add_host(host: str, exist_ok: bool = False, quiet: bool = False) -> bool:
    host = sanitize(host)
    host_dir = DEPLOY_ROOT / host
    config_dir = host_dir / "config"
    logs_dir = host_dir / "logs"
    runner_path = host_dir / "run_honeypot.py"

    if not BASE_CONFIG_DIR.exists():
        raise FileNotFoundError(f"Base config directory {BASE_CONFIG_DIR} not found.")
    if not BASE_RUNNER.exists():
        raise FileNotFoundError(f"Base runner {BASE_RUNNER} not found.")

    if host_dir.exists():
        if not exist_ok:
            raise FileExistsError(
                f"Deployment directory '{host_dir}' already exists. Remove it or use bulk mode with --skip-existing."
            )
        if not quiet:
            print(f"[=] Host '{host}' already prepared. Skipping.")
        return False

    DEPLOY_ROOT.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE_CONFIG_DIR, config_dir, ignore=shutil.ignore_patterns("logs", "logs/*"))
    update_log_paths(config_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)
    copy_certs(host_dir)
    copy_static_assets(host_dir)
    write_runner(runner_path)

    if not quiet:
        print(f"[+] Host '{host}' prepared in {host_dir}:")
        print(f"    - Config: {config_dir}")
        print(f"    - Logs:   {logs_dir}")
        print(f"    - Runner: {runner_path}")

    return True


def write_runner(runner_path: Path) -> None:
    runner_path.parent.mkdir(parents=True, exist_ok=True)
    template = """#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    repo_root = base_dir.parents[1]
    config_dir = base_dir / "config"
    runner = repo_root / "run_honeypot.py"
    if not runner.exists():
        raise FileNotFoundError(f"Base runner not found at {runner}")

    sys.path.insert(0, str(repo_root))
    from run_honeypot import main as base_main  # noqa: WPS433

    sys.argv = [str(runner), "--config-dir", str(config_dir), *sys.argv[1:]]
    base_main()


if __name__ == "__main__":
    main()
"""
    runner_path.write_text(template, encoding="utf-8")
    runner_path.chmod(runner_path.stat().st_mode | 0o111)


def update_log_paths(config_dir: Path) -> None:
    for entry in config_dir.glob("*_config.json"):
        try:
            data = json.loads(entry.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        service = entry.stem.replace("_config", "")
        if "log_file" in data:
            data["log_file"] = f"../logs/{service}.log"
            entry.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # filesystem/perception rules do not reference logs.


def copy_certs(host_dir: Path) -> None:
    source_certs = Path("certs")
    target_certs = host_dir / "certs"
    if not source_certs.exists():
        return
    if target_certs.exists():
        shutil.rmtree(target_certs)
    shutil.copytree(source_certs, target_certs)


def copy_static_assets(host_dir: Path) -> None:
    for static_dir in STATIC_DIRS:
        src = static_dir
        if not src.exists():
            continue
        dest = host_dir / static_dir.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)


def bulk_add(prefix: str, count: int, start: int = 1, width: int = 0, skip_existing: bool = True) -> None:
    created = 0
    skipped = 0
    for idx in range(start, start + count):
        host = format_host(prefix, idx, width)
        try:
            if add_host(host, exist_ok=skip_existing, quiet=True):
                created += 1
                print(f"[+] Created host '{host}'")
            else:
                skipped += 1
        except FileExistsError:
            skipped += 1
            print(f"[=] Host '{host}' already exists. Skipping.")
    print(f"[summary] created={created} skipped={skipped} total={count}")


def format_host(prefix: str, idx: int, width: int) -> str:
    return f"{prefix}{str(idx).zfill(width) if width > 0 else idx}"


def topology_hosts(topology_path: Path, skip_existing: bool = True) -> None:
    topology_path = topology_path.resolve()
    if not topology_path.exists():
        raise FileNotFoundError(f"Topology file not found: {topology_path}")
    try:
        data = json.loads(topology_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse topology JSON {topology_path}: {exc}") from exc

    raw_hosts = data.get("hosts", [])
    host_names: list[str] = []
    for entry in raw_hosts:
        if isinstance(entry, dict):
            name = entry.get("name")
        else:
            name = entry
        if isinstance(name, str) and name.strip():
            host_names.append(name.strip())

    if not host_names:
        print(f"[!] No hosts discovered in topology {topology_path}")
        return

    seen: set[str] = set()
    created = 0
    skipped = 0
    for name in host_names:
        if name in seen:
            continue
        seen.add(name)
        try:
            if add_host(name, exist_ok=skip_existing, quiet=True):
                created += 1
                print(f"[+] Created host '{name}' from topology")
            else:
                skipped += 1
                if not skip_existing:
                    print(f"[=] Host '{name}' already exists. Skipping.")
        except FileExistsError:
            skipped += 1
            if skip_existing:
                print(f"[=] Host '{name}' already exists. Skipping.")
            else:
                raise
    total = created + skipped
    print(f"[summary] topology_hosts created={created} skipped={skipped} total={total}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage per-host honeypot deployments.")
    sub = parser.add_subparsers(dest="command", required=True)

    add_cmd = sub.add_parser("add", help="Create host-specific deployment")
    add_cmd.add_argument("host", help="Host identifier (e.g., h1, host02)")

    bulk_cmd = sub.add_parser("bulk", help="Create multiple deployments")
    bulk_cmd.add_argument("--prefix", required=True, help="Host prefix, e.g., h")
    bulk_cmd.add_argument("--count", type=int, required=True, help="Number of hosts to create")
    bulk_cmd.add_argument("--start", type=int, default=1, help="Starting index (default: 1)")
    bulk_cmd.add_argument("--width", type=int, default=0, help="Zero-pad width (e.g., 2 => h01)")
    bulk_cmd.add_argument(
        "--no-skip-existing",
        action="store_true",
        help="Abort if deployment already exists (default skips existing hosts).",
    )

    topo_cmd = sub.add_parser("from-topology", help="Generate deployments from shadow topology hosts")
    topo_cmd.add_argument(
        "--topology",
        type=Path,
        default=Path("shadow/shadow_topology.json"),
        help="Shadow topology JSON path (default: shadow/shadow_topology.json)",
    )
    topo_cmd.add_argument(
        "--no-skip-existing",
        action="store_true",
        help="Abort if a deployment already exists for a host (default skips existing hosts).",
    )

    return parser.parse_args(argv)


def main(argv: list[str]) -> None:
    args = parse_args(argv)

    if args.command == "add":
        add_host(args.host)
    elif args.command == "bulk":
        if args.count <= 0:
            raise ValueError("Count must be positive.")
        skip_existing = not args.no_skip_existing
        bulk_add(
            prefix=args.prefix,
            count=args.count,
            start=args.start,
            width=args.width,
            skip_existing=skip_existing,
        )
    elif args.command == "from-topology":
        topology_hosts(args.topology, skip_existing=not args.no_skip_existing)
    else:
        raise ValueError(f"Unsupported command {args.command}")


if __name__ == "__main__":
    main(sys.argv[1:])
