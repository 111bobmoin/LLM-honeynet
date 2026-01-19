from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from perception import ShadowRAGStore


def load_enterprise_topology(enterprise_dir: Path) -> dict:
    topo_path = enterprise_dir / "enterprise_topology.json"
    if not topo_path.exists():
        raise FileNotFoundError(f"Enterprise topology file not found: {topo_path}")
    try:
        return json.loads(topo_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse enterprise topology JSON ({topo_path}): {exc}") from exc


def build_shadow_topology(topology: dict) -> dict:
    metadata = topology.get("metadata", {})

    switches: List[str] = []
    for sw in topology.get("switches", []):
        if isinstance(sw, dict):
            name = sw.get("id") or sw.get("name")
        else:
            name = sw
        if name:
            switches.append(name)

    hosts: List[Any] = []
    for host in topology.get("hosts", []):
        if isinstance(host, dict):
            entry = {k: v for k, v in host.items() if v not in (None, "", [])}
            if "name" not in entry and "id" in entry:
                entry["name"] = entry["id"]
            hosts.append(entry)
        else:
            hosts.append({"name": host})

    links: List[Dict[str, Any]] = []
    seen_links: Set[frozenset[str]] = set()
    for link in topology.get("links", []):
        if isinstance(link, dict):
            if "endpoints" in link and isinstance(link["endpoints"], list):
                endpoints = link["endpoints"]
            else:
                endpoints = [link.get("node1"), link.get("node2")]
        elif isinstance(link, (list, tuple)) and len(link) == 2:
            endpoints = list(link)
        else:
            endpoints = []
        if len(endpoints) == 2 and endpoints[0] and endpoints[1]:
            node1, node2 = endpoints
            key = frozenset((node1, node2))
            if key in seen_links:
                continue
            seen_links.add(key)
            links.append({"node1": node1, "node2": node2})

    return {
        "metadata": metadata,
        "switches": switches,
        "hosts": hosts,
        "links": links,
    }


def write_shadow_artifacts(shadow_topology: dict, output_dir: Path) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    topology_path = output_dir / "shadow_topology.json"
    with topology_path.open("w", encoding="utf-8") as handle:
        json.dump(shadow_topology, handle, indent=2, ensure_ascii=False)

    mininet_path = output_dir / "mininet_shadow.py"
    mininet_path.write_text(render_mininet_script(shadow_topology), encoding="utf-8")
    mininet_path.chmod(mininet_path.stat().st_mode | 0o111)

    return topology_path, mininet_path


def render_mininet_script(topology: dict) -> str:
    topo_json = json.dumps(topology, ensure_ascii=False)
    return f"""#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from contextlib import suppress

from mininet.clean import cleanup
from mininet.cli import CLI
from mininet.link import Link
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.topo import Topo


TOPOLOGY = {topo_json}


class ShortIntfLink(Link):
    @staticmethod
    def _sanitize(name: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9]", "", name)
        return cleaned or "iface"

    def intfName(self, node, n):
        suffix = f"-p{{n}}"
        base = self._sanitize(node.name)
        limit = 15 - len(suffix)
        if limit <= 0:
            raise ValueError("Interface suffix too long")
        if len(base) > limit:
            digest = hashlib.md5(base.encode()).hexdigest()[:4]
            base = f"{{base[:limit-4]}}{{digest}}"
        return f"{{base[:limit]}}{{suffix}}"


class ShadowTopo(Topo):
    def build(self):
        switches = {{}}
        hosts = {{}}
        explicit_links = []
        for link in TOPOLOGY.get("links", []):
            node1 = link.get("node1")
            node2 = link.get("node2")
            if node1 and node2:
                explicit_links.append((node1, node2))
        for idx, sw in enumerate(TOPOLOGY.get("switches", []), start=1):
            dpid = format(idx, "016x")
            switches[sw] = self.addSwitch(sw, dpid=dpid)

        for host in TOPOLOGY.get("hosts", []):
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

        for host in TOPOLOGY.get("hosts", []):
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


def main():
    setLogLevel("info")
    cleanup()
    topo = ShadowTopo()
    net = Mininet(topo=topo, switch=OVSBridge, controller=None, link=ShortIntfLink)
    try:
        net.start()
        CLI(net)
    finally:
        with suppress(Exception):
            net.stop()
        cleanup()


if __name__ == "__main__":
    main()
"""


def update_rag_cache(topology: dict, source: str = "enterprise-file", store_path: Optional[Path] = None) -> Path:
    store = ShadowRAGStore(store_path=store_path) if store_path else ShadowRAGStore()
    store.add_topology(topology, source=source)
    return store.store_path

