# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

"""The test engine: for each rule in the policy, probe from the 'from'
VLAN's sub-interface towards a target on the 'to' VLAN (or the internet),
and compare what actually happened against what the policy expects.

Like interfaces.py, this is split into a Prober ABC plus Real/Mock
backends so the rule-evaluation logic (which is the part worth getting
right and testing) can be exercised without root or real hardware.
"""
from __future__ import annotations

import abc
import logging
import socket
import subprocess

from vlanprobe.discovery import HostDiscoverer
from vlanprobe.models import (
    INTERNET_TARGET,
    Expectation,
    InterfaceStatus,
    ProbeOutcome,
    ProbeResult,
    RuleResult,
    Verdict,
)
from vlanprobe.schema import Policy, RuleConfig

log = logging.getLogger("vlanprobe.testengine")

PING_TIMEOUT_S = 2
TCP_TIMEOUT_S = 2


class Prober(abc.ABC):
    @abc.abstractmethod
    def ping(self, ifname: str, target_ip: str) -> ProbeResult: ...

    @abc.abstractmethod
    def tcp_connect(self, ifname: str, target_ip: str, port: int) -> ProbeResult: ...


class RealProber(Prober):
    """Linux backend. TCP connects are bound to the source sub-interface
    via SO_BINDTODEVICE so the OS routing table can't accidentally send
    the probe out the wrong VLAN (which would silently invalidate the
    test). Requires root for SO_BINDTODEVICE and for ping in some
    configurations."""

    def ping(self, ifname: str, target_ip: str) -> ProbeResult:
        result = subprocess.run(
            ["ping", "-c", "2", "-W", str(PING_TIMEOUT_S), "-I", ifname, target_ip],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return ProbeResult("ping", None, ProbeOutcome.REACHABLE, detail="ICMP echo reply received")
        if "unreachable" in result.stdout.lower() or "unreachable" in result.stderr.lower():
            return ProbeResult("ping", None, ProbeOutcome.UNREACHABLE, detail=result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "destination unreachable")
        return ProbeResult("ping", None, ProbeOutcome.TIMEOUT, detail="no reply within timeout")

    def tcp_connect(self, ifname: str, target_ip: str, port: int) -> ProbeResult:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_BINDTODEVICE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
            sock.settimeout(TCP_TIMEOUT_S)
            err = sock.connect_ex((target_ip, port))
            if err == 0:
                return ProbeResult("tcp", port, ProbeOutcome.REACHABLE, detail="TCP handshake completed")
            if err in (110, 111):  # ETIMEDOUT, ECONNREFUSED
                outcome = ProbeOutcome.TIMEOUT if err == 110 else ProbeOutcome.UNREACHABLE
                detail = "connection refused (host reachable, port closed)" if err == 111 else "connection timed out"
                return ProbeResult("tcp", port, outcome, detail=detail)
            return ProbeResult("tcp", port, ProbeOutcome.UNREACHABLE, detail=f"connect failed (errno {err})")
        except (TimeoutError, socket.timeout):
            return ProbeResult("tcp", port, ProbeOutcome.TIMEOUT, detail="connection timed out")
        except OSError as exc:
            return ProbeResult("tcp", port, ProbeOutcome.UNREACHABLE, detail=str(exc))
        finally:
            sock.close()


class MockProber(Prober):
    """Dry-run backend. Defaults every probe to REACHABLE — i.e. it
    simulates an *unsegmented* network, which is the pessimistic/safe
    default and happens to be a good demo of the report's VIOLATED
    highlighting. Pass `overrides` (keyed by (ifname, target_ip, kind,
    port)) to script specific outcomes, e.g. in tests."""

    def __init__(self, default_outcome: ProbeOutcome = ProbeOutcome.REACHABLE,
                 overrides: dict[tuple[str, str, str, int | None], ProbeOutcome] | None = None):
        self.default_outcome = default_outcome
        self.overrides = overrides or {}

    def _outcome(self, ifname: str, target_ip: str, kind: str, port: int | None) -> ProbeOutcome:
        return self.overrides.get((ifname, target_ip, kind, port), self.default_outcome)

    def ping(self, ifname: str, target_ip: str) -> ProbeResult:
        outcome = self._outcome(ifname, target_ip, "ping", None)
        return ProbeResult("ping", None, outcome, detail="[dry-run] simulated")

    def tcp_connect(self, ifname: str, target_ip: str, port: int) -> ProbeResult:
        outcome = self._outcome(ifname, target_ip, "tcp", port)
        return ProbeResult("tcp", port, outcome, detail="[dry-run] simulated")


class TestEngine:
    __test__ = False  # not a pytest test case, just named similarly

    def __init__(self, policy: Policy, prober: Prober, discoverer: HostDiscoverer,
                 interface_statuses: dict[str, InterfaceStatus]):
        self.policy = policy
        self.prober = prober
        self.discoverer = discoverer
        self.interface_statuses = interface_statuses

    def run(self) -> list[RuleResult]:
        return [self._run_rule(i, rule) for i, rule in enumerate(self.policy.rules)]

    def _run_rule(self, index: int, rule: RuleConfig) -> RuleResult:
        result = RuleResult(rule_index=index, from_vlan=rule.from_, to_vlan=rule.to, expect=rule.expect)

        from_status = self.interface_statuses.get(rule.from_)
        if from_status is None or not from_status.usable:
            result.verdict = Verdict.INCONCLUSIVE
            reason = from_status.error if from_status and from_status.error else "sub-interface was not configured"
            result.notes = (f"Could not test from '{rule.from_}': its VLAN sub-interface never obtained a "
                             f"usable IP address ({reason}).")
            return result

        target_ip, test_ports, err = self._resolve_target(rule, result)
        if err:
            result.verdict = Verdict.INCONCLUSIVE
            result.notes = err
            return result
        result.target_ip = target_ip

        if self.policy.defaults.ping:
            result.probes.append(self.prober.ping(from_status.ifname, target_ip))

        for port in test_ports:
            result.probes.append(self.prober.tcp_connect(from_status.ifname, target_ip, port))
            result.ports_tested.append(port)

        actual_allow = result.actual_reachable
        expected_allow = rule.expect == Expectation.ALLOW

        if actual_allow == expected_allow:
            result.verdict = Verdict.HELD
            result.notes = _held_note(rule, actual_allow)
        else:
            result.verdict = Verdict.VIOLATED
            result.notes = _violation_note(rule, actual_allow)

        return result

    def _resolve_target(self, rule: RuleConfig, result: RuleResult) -> tuple[str | None, list[int], str | None]:
        """Returns (target_ip, ports_to_test, error_message). error_message
        is set (and the other two ignored) when the rule can't be tested."""
        if rule.to == INTERNET_TARGET:
            return self.policy.defaults.internet_target, [self.policy.defaults.internet_port], None

        to_vlan = self.policy.vlan_by_name(rule.to)
        ports = self.policy.effective_ports(rule)

        if to_vlan.target_ip:
            return to_vlan.target_ip, ports, None

        to_status = self.interface_statuses.get(rule.to)
        if to_status is None or not to_status.usable:
            return None, [], (f"Could not test towards '{rule.to}': no target_ip is configured for it in the "
                               f"policy, and its own sub-interface has no address to discover a host from.")

        result.target_discovered = True
        own_ip = to_status.address.split("/")[0] if to_status.address else None
        discovered = self.discoverer.discover(to_status.ifname, to_status.address, exclude_ip=own_ip)
        if discovered is None:
            return None, [], (f"Could not test towards '{rule.to}': no target_ip is configured for it, and no "
                               f"live host could be discovered on that VLAN to test against.")
        return discovered, ports, None


def _held_note(rule: RuleConfig, actual_allow: bool) -> str:
    if actual_allow:
        return f"Traffic from '{rule.from_}' to '{rule.to}' was reachable, matching the policy (which allows it)."
    return f"Traffic from '{rule.from_}' to '{rule.to}' was blocked, matching the policy (which denies it)."


def _violation_note(rule: RuleConfig, actual_allow: bool) -> str:
    if actual_allow:
        return (f"'{rule.from_}' was able to reach '{rule.to}', but policy requires this to be denied. "
                f"This VLAN boundary is not actually enforced.")
    return (f"'{rule.from_}' could not reach '{rule.to}', but policy requires this to be allowed. "
            f"This may be an over-restrictive firewall/ACL blocking legitimate traffic.")
