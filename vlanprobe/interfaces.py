# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

"""VLAN tagged sub-interface orchestration.

Two implementations share one interface (`InterfaceManager`):

  - RealInterfaceManager: actually runs `ip link` / `dhclient` on Linux.
  - DryRunInterfaceManager: logs what it would do and fabricates plausible
    results, so the test engine and report layers can be built and
    exercised without root, without Linux, and without a real trunk port.

Everything downstream (testengine.py) only ever talks to the
`InterfaceManager` ABC, so swapping real <-> dry-run is a one-line change
in cli.py.
"""
from __future__ import annotations

import abc
import logging
import subprocess
from dataclasses import dataclass

from vlanprobe.models import InterfaceStatus, IPAssignMethod
from vlanprobe.schema import VlanConfig

log = logging.getLogger("vlanprobe.interfaces")


def subif_name(trunk: str, vlan_id: int) -> str:
    return f"{trunk}.{vlan_id}"


class InterfaceManager(abc.ABC):
    """Brings up (and later tears down) one tagged sub-interface per VLAN
    in the policy, on the given trunk NIC."""

    def __init__(self, trunk_interface: str, dhcp_timeout_default: int):
        self.trunk_interface = trunk_interface
        self.dhcp_timeout_default = dhcp_timeout_default
        self._created: list[str] = []  # ifnames we created, for teardown

    def setup(self, vlans: list[VlanConfig]) -> dict[str, InterfaceStatus]:
        """Create + address a sub-interface for every VLAN. Returns a dict
        keyed by VLAN name. Never raises for an individual VLAN failing to
        get an address — that's recorded as IPAssignMethod.NONE on the
        InterfaceStatus, not an exception, because it's expected/useful
        audit information rather than a tool error."""
        statuses: dict[str, InterfaceStatus] = {}
        for vlan in vlans:
            statuses[vlan.name] = self._setup_one(vlan)
        return statuses

    def teardown(self) -> None:
        for ifname in reversed(self._created):
            self._delete_subif(ifname)
        self._created.clear()

    def _setup_one(self, vlan: VlanConfig) -> InterfaceStatus:
        ifname = subif_name(self.trunk_interface, vlan.id)
        self._create_subif(ifname, vlan.id)
        self._created.append(ifname)
        self._bring_up(ifname)

        timeout = vlan.dhcp_timeout if vlan.dhcp_timeout is not None else self.dhcp_timeout_default

        if vlan.dhcp:
            addr = self._try_dhcp(ifname, timeout)
            if addr:
                return InterfaceStatus(vlan.id, vlan.name, ifname, IPAssignMethod.DHCP, address=addr)
            log.info("%s: DHCP did not produce an address within %ss", ifname, timeout)

        if vlan.static:
            self._assign_static(ifname, vlan.static.address, vlan.static.gateway)
            return InterfaceStatus(vlan.id, vlan.name, ifname, IPAssignMethod.STATIC, address=vlan.static.address)

        note = "DHCP disabled and no static fallback configured" if not vlan.dhcp else "DHCP timed out and no static fallback configured"
        return InterfaceStatus(vlan.id, vlan.name, ifname, IPAssignMethod.NONE, error=note)

    # -- primitives each backend implements -------------------------------

    @abc.abstractmethod
    def _create_subif(self, ifname: str, vlan_id: int) -> None: ...

    @abc.abstractmethod
    def _bring_up(self, ifname: str) -> None: ...

    @abc.abstractmethod
    def _try_dhcp(self, ifname: str, timeout: int) -> str | None:
        """Returns the assigned CIDR address, or None if DHCP failed."""

    @abc.abstractmethod
    def _assign_static(self, ifname: str, cidr: str, gateway: str | None) -> None: ...

    @abc.abstractmethod
    def _delete_subif(self, ifname: str) -> None: ...


class RealInterfaceManager(InterfaceManager):
    """Linux backend. Requires root / CAP_NET_ADMIN, `ip` (iproute2), and
    a DHCP client (`dhclient` or `dhcpcd`) on PATH."""

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        log.debug("+ %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"command failed ({' '.join(cmd)}): {result.stderr.strip()}")
        return result

    def _create_subif(self, ifname: str, vlan_id: int) -> None:
        # Ignore "file exists" so re-running against a leftover interface
        # from a previous crashed run doesn't hard-fail.
        result = subprocess.run(
            ["ip", "link", "add", "link", self.trunk_interface, "name", ifname, "type", "vlan", "id", str(vlan_id)],
            capture_output=True, text=True,
        )
        if result.returncode != 0 and "File exists" not in result.stderr:
            raise RuntimeError(f"failed to create {ifname}: {result.stderr.strip()}")

    def _bring_up(self, ifname: str) -> None:
        self._run(["ip", "link", "set", ifname, "up"])

    def _try_dhcp(self, ifname: str, timeout: int) -> str | None:
        client = _find_dhcp_client()
        if client is None:
            log.warning("no DHCP client (dhclient/dhcpcd) found on PATH")
            return None
        try:
            if client == "dhclient":
                subprocess.run(["dhclient", "-1", "-timeout", str(timeout), ifname], capture_output=True, text=True)
            else:
                subprocess.run(["dhcpcd", "-t", str(timeout), ifname], capture_output=True, text=True)
        except FileNotFoundError:
            return None
        return self._current_address(ifname)

    def _current_address(self, ifname: str) -> str | None:
        result = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", ifname], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if "inet" in parts:
                return parts[parts.index("inet") + 1]
        return None

    def _assign_static(self, ifname: str, cidr: str, gateway: str | None) -> None:
        subprocess.run(["ip", "addr", "flush", "dev", ifname], capture_output=True, text=True)
        self._run(["ip", "addr", "add", cidr, "dev", ifname])
        if gateway:
            # Best-effort: a route via this gateway scoped to this link.
            subprocess.run(["ip", "route", "add", "default", "via", gateway, "dev", ifname, "metric", "500"],
                            capture_output=True, text=True)

    def _delete_subif(self, ifname: str) -> None:
        subprocess.run(["ip", "link", "delete", ifname], capture_output=True, text=True)


def _find_dhcp_client() -> str | None:
    import shutil
    if shutil.which("dhclient"):
        return "dhclient"
    if shutil.which("dhcpcd"):
        return "dhcpcd"
    return None


@dataclass
class DryRunAction:
    description: str


class DryRunInterfaceManager(InterfaceManager):
    """Logs every action it *would* take instead of touching the system.
    Fabricates a plausible outcome per VLAN so the rest of the pipeline
    (test engine, report) has realistic data to run against:

      - if the VLAN has a static block configured, "succeeds" via static
      - otherwise, if dhcp is enabled, "succeeds" via DHCP with a made-up
        address in a private range derived from the VLAN id
      - otherwise, no address at all (matches the real NONE case)
    """

    def __init__(self, trunk_interface: str, dhcp_timeout_default: int):
        super().__init__(trunk_interface, dhcp_timeout_default)
        self.actions: list[DryRunAction] = []

    def _log(self, msg: str) -> None:
        self.actions.append(DryRunAction(msg))
        log.info("[dry-run] %s", msg)

    def _create_subif(self, ifname: str, vlan_id: int) -> None:
        self._log(f"would run: ip link add link {self.trunk_interface} name {ifname} type vlan id {vlan_id}")

    def _bring_up(self, ifname: str) -> None:
        self._log(f"would run: ip link set {ifname} up")

    def _try_dhcp(self, ifname: str, timeout: int) -> str | None:
        self._log(f"would attempt DHCP on {ifname} (timeout {timeout}s)")
        return None  # resolved in _setup_one's fabrication logic below

    def _assign_static(self, ifname: str, cidr: str, gateway: str | None) -> None:
        self._log(f"would run: ip addr add {cidr} dev {ifname}" + (f" (gw {gateway})" if gateway else ""))

    def _delete_subif(self, ifname: str) -> None:
        self._log(f"would run: ip link delete {ifname}")

    def _setup_one(self, vlan: VlanConfig) -> InterfaceStatus:
        ifname = subif_name(self.trunk_interface, vlan.id)
        self._create_subif(ifname, vlan.id)
        self._created.append(ifname)
        self._bring_up(ifname)

        if vlan.dhcp:
            self._log(f"would attempt DHCP on {ifname}")
            fabricated = f"10.255.{vlan.id % 256}.100/24"
            self._log(f"[simulated] DHCP succeeded on {ifname}: {fabricated}")
            return InterfaceStatus(vlan.id, vlan.name, ifname, IPAssignMethod.DHCP, address=fabricated)

        if vlan.static:
            self._assign_static(ifname, vlan.static.address, vlan.static.gateway)
            return InterfaceStatus(vlan.id, vlan.name, ifname, IPAssignMethod.STATIC, address=vlan.static.address)

        note = "DHCP disabled and no static fallback configured (simulated)"
        self._log(f"{ifname}: {note}")
        return InterfaceStatus(vlan.id, vlan.name, ifname, IPAssignMethod.NONE, error=note)


def build_interface_manager(dry_run: bool, trunk_interface: str, dhcp_timeout_default: int) -> InterfaceManager:
    if dry_run:
        return DryRunInterfaceManager(trunk_interface, dhcp_timeout_default)
    return RealInterfaceManager(trunk_interface, dhcp_timeout_default)
