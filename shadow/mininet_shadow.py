#!/usr/bin/env python3
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


TOPOLOGY = {"metadata": {"name": "Enterprise Production Segment", "description": "Canonical enterprise network used to derive shadow honeynet topology", "version": "2024.10"}, "switches": ["core-sw", "dmz-sw", "corp-sw"], "hosts": [{"name": "edge-fw", "role": "firewall", "connect": "core-sw"}, {"name": "bastion-01", "role": "bastion", "connect": "corp-sw"}, {"name": "jump-ops", "role": "operations", "connect": "corp-sw"}, {"name": "dmz-web-01", "role": "public-web", "connect": "dmz-sw"}, {"name": "dmz-api-01", "role": "public-api", "connect": "dmz-sw"}, {"name": "app-01", "role": "application", "connect": "corp-sw"}, {"name": "db-01", "role": "database", "connect": "corp-sw"}, {"name": "fileserver-01", "role": "fileserver", "connect": "corp-sw"}], "links": [{"node1": "core-sw", "node2": "dmz-sw"}, {"node1": "core-sw", "node2": "corp-sw"}, {"node1": "core-sw", "node2": "edge-fw"}, {"node1": "dmz-sw", "node2": "dmz-web-01"}, {"node1": "dmz-sw", "node2": "dmz-api-01"}, {"node1": "corp-sw", "node2": "bastion-01"}, {"node1": "corp-sw", "node2": "jump-ops"}, {"node1": "corp-sw", "node2": "app-01"}, {"node1": "corp-sw", "node2": "db-01"}, {"node1": "corp-sw", "node2": "fileserver-01"}]}


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
    def build(self):
        switches = {}
        hosts = {}
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
