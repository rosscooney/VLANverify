# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

"""Core data types shared across the policy, interface, test-engine and
report layers. Kept dependency-free (stdlib only) so every other module can
import from here without pulling in pydantic/jinja2/etc.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


INTERNET_TARGET = "internet"


class Expectation(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


class Verdict(str, enum.Enum):
    HELD = "HELD"
    VIOLATED = "VIOLATED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ProbeOutcome(str, enum.Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"


class IPAssignMethod(str, enum.Enum):
    DHCP = "dhcp"
    STATIC = "static"
    NONE = "none"  # could not obtain an address by any method


@dataclass
class InterfaceStatus:
    """Result of bringing up the tagged sub-interface for one VLAN."""
    vlan_id: int
    vlan_name: str
    ifname: str
    method: IPAssignMethod
    address: str | None = None  # CIDR, e.g. "10.0.10.5/24"
    error: str | None = None    # human-readable note when method is NONE

    @property
    def usable(self) -> bool:
        return self.method != IPAssignMethod.NONE and self.address is not None


@dataclass
class ProbeResult:
    """Result of a single ping or TCP-connect attempt."""
    kind: str  # "ping" or "tcp"
    port: int | None  # None for ping
    outcome: ProbeOutcome
    detail: str = ""


@dataclass
class RuleResult:
    rule_index: int
    from_vlan: str
    to_vlan: str
    expect: Expectation
    ports_tested: list[int] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)
    target_ip: str | None = None
    target_discovered: bool = False
    verdict: Verdict = Verdict.INCONCLUSIVE
    notes: str = ""

    @property
    def actual_reachable(self) -> bool:
        """True if any probe (ping or TCP) got through."""
        return any(p.outcome == ProbeOutcome.REACHABLE for p in self.probes)

    @property
    def is_security_violation(self) -> bool:
        """A VIOLATED result where traffic that should have been blocked
        got through — the critical, headline finding for an audit. The
        other VIOLATED case (traffic that should be allowed was blocked)
        is still worth flagging, but it's an availability/config issue,
        not a segmentation failure."""
        return self.verdict == Verdict.VIOLATED and self.expect == Expectation.DENY


@dataclass
class ScanReport:
    generated_at: str
    device_interface: str
    policy_path: str
    policy_hash: str
    dry_run: bool
    interface_statuses: list[InterfaceStatus]
    rule_results: list[RuleResult]

    @property
    def summary_counts(self) -> dict[str, int]:
        counts = {v.value: 0 for v in Verdict}
        for r in self.rule_results:
            counts[r.verdict.value] += 1
        return counts
