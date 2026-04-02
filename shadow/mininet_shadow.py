#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import time
from contextlib import suppress
from pathlib import Path

DEFAULT_TOPOLOGY_PATH = Path(__file__).with_name("shadow_topology.json")
DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parent.parent

try:
    from mininet.clean import cleanup
    from mininet.cli import CLI
    from mininet.link import Link
    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSBridge
    from mininet.topo import Topo
except Exception as exc:  # noqa: BLE001
    cleanup = CLI = Link = setLogLevel = Mininet = OVSBridge = Topo = None
    MININET_IMPORT_ERROR = exc
else:
    MININET_IMPORT_ERROR = None


def load_topology(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class ShortIntfLink(Link):
    @staticmethod
    def _sanitize(name: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9]", "", name)
        return cleaned or "iface"

    def intfName(self, node, n):
        suffix = f"-p{n}"
        base = self._sanitize(node.name)
        limit = 15 - len(suffix)
        if limit <= 0:
            raise ValueError("Interface suffix too long")
        if len(base) > limit:
            digest = hashlib.md5(base.encode()).hexdigest()[:4]
            base = f"{base[:limit-4]}{digest}"
        return f"{base[:limit]}{suffix}"


class ShadowTopo(Topo):
    def __init__(self, topology: dict):
        self.topology = topology
        super().__init__()

    def build(self):
        switches = {}
        hosts = {}
        explicit_links = []
        for link in self.topology.get("links", []):
            node1 = link.get("node1")
            node2 = link.get("node2")
            if node1 and node2:
                explicit_links.append((node1, node2))
        for idx, sw in enumerate(self.topology.get("switches", []), start=1):
            dpid = format(idx, "016x")
            switches[sw] = self.addSwitch(sw, dpid=dpid)

        for host in self.topology.get("hosts", []):
            name = host.get("name") if isinstance(host, dict) else host
            hosts[name] = self.addHost(name)

        seen_links = set()

        for node1, node2 in explicit_links:
            endpoint1 = switches.get(node1) or hosts.get(node1)
            endpoint2 = switches.get(node2) or hosts.get(node2)
            if endpoint1 and endpoint2:
                pair = frozenset((node1, node2))
                if pair in seen_links:
                    continue
                self.addLink(endpoint1, endpoint2)
                seen_links.add(pair)

        for host in self.topology.get("hosts", []):
            if not isinstance(host, dict):
                continue
            name = host.get("name")
            connect = host.get("connect")
            if not name or not connect:
                continue
            pair = frozenset((name, connect))
            if pair in seen_links:
                continue
            endpoint1 = hosts.get(name)
            endpoint2 = switches.get(connect) or hosts.get(connect)
            if endpoint1 and endpoint2:
                self.addLink(endpoint1, endpoint2)
                seen_links.add(pair)


def parse_args():
    parser = argparse.ArgumentParser(description="Launch Mininet shadow topology")
    parser.add_argument("--topology", type=Path, default=DEFAULT_TOPOLOGY_PATH, help="Path to shadow_topology.json")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=DEFAULT_PROJECT_ROOT,
        help="Project root containing deployments/ and run_honeypot.py",
    )
    parser.add_argument(
        "--start-honeypots",
        action="store_true",
        help="Start each deployment's honeypot services inside its corresponding Mininet host namespace.",
    )
    parser.add_argument("--no-cli", action="store_true", help="Start the topology without dropping into CLI")
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="When used with --no-cli, keep the network alive for N seconds before stopping (0 means return immediately after start).",
    )
    return parser.parse_args()


def start_honeypots(net, project_root: Path) -> tuple[dict[str, subprocess.Popen], dict[str, object]]:
    processes: dict[str, subprocess.Popen] = {}
    log_handles: dict[str, object] = {}
    deployments_root = project_root / "deployments"

    for host in net.hosts:
        deployment_dir = deployments_root / host.name
        config_dir = deployment_dir / "config"
        if not config_dir.exists():
            print(f"[!] Skipping {host.name}: deployment config not found at {config_dir}")
            continue

        logs_dir = deployment_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        runtime_log = logs_dir / "honeypot_runtime.log"
        handle = runtime_log.open("a", encoding="utf-8")
        command = f"cd {shlex.quote(str(project_root))} && python3 run_honeypot.py --deployment {shlex.quote(host.name)}"
        process = host.popen(
            ["bash", "-lc", command],
            cwd=str(project_root),
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
        processes[host.name] = process
        log_handles[host.name] = handle
        print(f"[+] Started honeypot on {host.name} (pid={process.pid}) -> {runtime_log}")

    time.sleep(1.0)
    for host_name, process in processes.items():
        if process.poll() is not None:
            print(f"[!] Honeypot on {host_name} exited early with code {process.returncode}")

    return processes, log_handles


def stop_honeypots(processes: dict[str, subprocess.Popen], log_handles: dict[str, object]) -> None:
    for process in processes.values():
        if process.poll() is None:
            with suppress(Exception):
                process.terminate()
    for process in processes.values():
        with suppress(Exception):
            process.wait(timeout=5)
    for handle in log_handles.values():
        with suppress(Exception):
            handle.close()


def main():
    args = parse_args()
    if MININET_IMPORT_ERROR is not None:
        raise RuntimeError(
            f"Mininet is unavailable. Install Mininet and required system dependencies first: {MININET_IMPORT_ERROR}"
        )
    topology = load_topology(args.topology)
    setLogLevel("info")
    cleanup()
    topo = ShadowTopo(topology)
    net = Mininet(topo=topo, switch=OVSBridge, controller=None, link=ShortIntfLink)
    honeypot_processes: dict[str, subprocess.Popen] = {}
    honeypot_logs: dict[str, object] = {}
    try:
        net.start()
        if args.start_honeypots:
            honeypot_processes, honeypot_logs = start_honeypots(net, args.project_root.resolve())
        if args.no_cli:
            if args.duration > 0:
                time.sleep(args.duration)
        else:
            CLI(net)
    finally:
        stop_honeypots(honeypot_processes, honeypot_logs)
        with suppress(Exception):
            net.stop()
        cleanup()


if __name__ == "__main__":
    main()
