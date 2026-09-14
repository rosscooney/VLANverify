# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

"""Live host discovery for VLANs where the policy doesn't specify a
target_ip. Used to find something on the target VLAN worth pinging/
port-scanning.

Approach on real hardware: ping-sweep the subnet (concurrently, short
timeout) to populate the kernel's neighbour table, then read that table
for anything that actually replied. This is deliberately simple — it's
not trying to be nmap, just to find *one* live host to test reachability
against.
"""
from __future__ import annotations

import abc
import ipaddress
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("vlanprobe.discovery")

# Don't sweep more than this many hosts — keeps a /16 typo from turning a
# scan into an hours-long ping storm.
MAX_SWEEP_HOSTS = 256
SWEEP_TIMEOUT_S = 1
SWEEP_CONCURRENCY = 32


class HostDiscoverer(abc.ABC):
    @abc.abstractmethod
    def discover(self, ifname: str, cidr: str, exclude_ip: str | None = None) -> str | None:
        """Return one live host IP on the given subnet, or None if none
        was found. `exclude_ip` is normally our own address on that
        sub-interface."""


class RealHostDiscoverer(HostDiscoverer):
    def discover(self, ifname: str, cidr: str, exclude_ip: str | None = None) -> str | None:
        try:
            network = ipaddress.ip_interface(cidr).network
        except ValueError:
            log.warning("cannot discover on %s: '%s' is not a valid CIDR", ifname, cidr)
            return None

        hosts = list(network.hosts())
        if exclude_ip:
            hosts = [h for h in hosts if str(h) != exclude_ip]
        if len(hosts) > MAX_SWEEP_HOSTS:
            log.info("%s: subnet has %d hosts, sweeping first %d only", ifname, len(hosts), MAX_SWEEP_HOSTS)
            hosts = hosts[:MAX_SWEEP_HOSTS]

        def ping_one(ip: str) -> bool:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(SWEEP_TIMEOUT_S), "-I", ifname, ip],
                capture_output=True, text=True,
            )
            return result.returncode == 0

        with ThreadPoolExecutor(max_workers=SWEEP_CONCURRENCY) as pool:
            results = pool.map(ping_one, (str(h) for h in hosts))
            for host, ok in zip(hosts, results):
                if ok:
                    log.info("%s: discovered live host %s", ifname, host)
                    return str(host)

        # Fall back to the neighbour table in case ICMP is filtered but
        # something still answered ARP during the sweep.
        result = subprocess.run(["ip", "neigh", "show", "dev", ifname], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            ip = parts[0]
            if ip == exclude_ip:
                continue
            if "REACHABLE" in line or "STALE" in line or "lladdr" in line:
                log.info("%s: discovered host %s via neighbour table", ifname, ip)
                return ip

        log.info("%s: no live host discovered on %s", ifname, cidr)
        return None


class DryRunHostDiscoverer(HostDiscoverer):
    """Fabricates a plausible live host inside the given subnet, so the
    dry-run pipeline has something to 'test' against."""

    def discover(self, ifname: str, cidr: str, exclude_ip: str | None = None) -> str | None:
        try:
            network = ipaddress.ip_interface(cidr).network
        except ValueError:
            return None
        hosts = list(network.hosts())
        if not hosts:
            return None
        candidate = str(hosts[min(49, len(hosts) - 1)])
        log.info("[dry-run] %s: simulated discovery found host %s", ifname, candidate)
        return candidate
