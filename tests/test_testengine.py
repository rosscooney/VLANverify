# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

import textwrap

from vlanprobe.discovery import DryRunHostDiscoverer, HostDiscoverer
from vlanprobe.models import IPAssignMethod, InterfaceStatus, ProbeOutcome, Verdict
from vlanprobe.schema import load_policy
from vlanprobe.testengine import MockProber, TestEngine


def make_policy(tmp_path, content: str):
    path = tmp_path / "policy.yaml"
    path.write_text(textwrap.dedent(content))
    return load_policy(path)


def usable_status(vlan_id, name, ifname, address="10.0.0.1/24"):
    return InterfaceStatus(vlan_id, name, ifname, IPAssignMethod.DHCP, address=address)


def unusable_status(vlan_id, name, ifname, error="no address"):
    return InterfaceStatus(vlan_id, name, ifname, IPAssignMethod.NONE, error=error)


class NoHostDiscoverer(HostDiscoverer):
    def discover(self, ifname, cidr, exclude_ip=None):
        return None


def test_deny_rule_blocked_is_held(tmp_path):
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: guest, target_ip: 10.0.10.5}
          - {id: 20, name: corp, target_ip: 10.0.20.5}
        rules:
          - {from: guest, to: corp, expect: deny}
    """)
    statuses = {
        "guest": usable_status(10, "guest", "eth0.10"),
        "corp": usable_status(20, "corp", "eth0.20"),
    }
    prober = MockProber(default_outcome=ProbeOutcome.UNREACHABLE)
    engine = TestEngine(policy, prober, DryRunHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].verdict == Verdict.HELD
    assert not results[0].is_security_violation


def test_deny_rule_reachable_is_a_security_violation(tmp_path):
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: guest, target_ip: 10.0.10.5}
          - {id: 20, name: corp, target_ip: 10.0.20.5}
        rules:
          - {from: guest, to: corp, expect: deny}
    """)
    statuses = {
        "guest": usable_status(10, "guest", "eth0.10"),
        "corp": usable_status(20, "corp", "eth0.20"),
    }
    prober = MockProber(default_outcome=ProbeOutcome.REACHABLE)
    engine = TestEngine(policy, prober, DryRunHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].verdict == Verdict.VIOLATED
    assert results[0].is_security_violation


def test_allow_rule_reachable_is_held(tmp_path):
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: corp, target_ip: 10.0.10.5}
          - {id: 20, name: iot, target_ip: 10.0.20.5}
        rules:
          - {from: corp, to: iot, expect: allow}
    """)
    statuses = {
        "corp": usable_status(10, "corp", "eth0.10"),
        "iot": usable_status(20, "iot", "eth0.20"),
    }
    prober = MockProber(default_outcome=ProbeOutcome.REACHABLE)
    engine = TestEngine(policy, prober, DryRunHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].verdict == Verdict.HELD
    assert not results[0].is_security_violation


def test_allow_rule_blocked_is_violated_but_not_a_security_violation(tmp_path):
    """An over-restrictive firewall blocking traffic that should be
    allowed is still a policy mismatch worth flagging, but it is not the
    same class of finding as a segmentation failure."""
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: corp, target_ip: 10.0.10.5}
          - {id: 20, name: iot, target_ip: 10.0.20.5}
        rules:
          - {from: corp, to: iot, expect: allow}
    """)
    statuses = {
        "corp": usable_status(10, "corp", "eth0.10"),
        "iot": usable_status(20, "iot", "eth0.20"),
    }
    prober = MockProber(default_outcome=ProbeOutcome.UNREACHABLE)
    engine = TestEngine(policy, prober, DryRunHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].verdict == Verdict.VIOLATED
    assert not results[0].is_security_violation


def test_inconclusive_when_source_vlan_has_no_address(tmp_path):
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: guest, target_ip: 10.0.10.5}
          - {id: 20, name: corp, target_ip: 10.0.20.5}
        rules:
          - {from: guest, to: corp, expect: deny}
    """)
    statuses = {
        "guest": unusable_status(10, "guest", "eth0.10"),
        "corp": usable_status(20, "corp", "eth0.20"),
    }
    prober = MockProber()
    engine = TestEngine(policy, prober, DryRunHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].verdict == Verdict.INCONCLUSIVE
    assert "guest" in results[0].notes


def test_inconclusive_when_no_target_and_no_live_host_discovered(tmp_path):
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: guest}
          - {id: 20, name: corp}
        rules:
          - {from: guest, to: corp, expect: deny}
    """)
    statuses = {
        "guest": usable_status(10, "guest", "eth0.10"),
        "corp": usable_status(20, "corp", "eth0.20"),
    }
    prober = MockProber()
    engine = TestEngine(policy, prober, NoHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].verdict == Verdict.INCONCLUSIVE


def test_internet_rule_uses_configured_internet_target(tmp_path):
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: guest}
        rules:
          - {from: guest, to: internet, expect: allow}
        defaults:
          internet_target: 9.9.9.9
          internet_port: 443
    """)
    statuses = {"guest": usable_status(10, "guest", "eth0.10")}
    prober = MockProber(default_outcome=ProbeOutcome.REACHABLE)
    engine = TestEngine(policy, prober, DryRunHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].target_ip == "9.9.9.9"
    assert results[0].ports_tested == [443]
    assert results[0].verdict == Verdict.HELD


def test_discovered_target_is_flagged_in_result(tmp_path):
    policy = make_policy(tmp_path, """
        vlans:
          - {id: 10, name: guest}
          - {id: 20, name: corp}
        rules:
          - {from: guest, to: corp, expect: deny}
    """)
    statuses = {
        "guest": usable_status(10, "guest", "eth0.10"),
        "corp": usable_status(20, "corp", "eth0.20", address="10.0.20.1/24"),
    }
    prober = MockProber(default_outcome=ProbeOutcome.UNREACHABLE)
    engine = TestEngine(policy, prober, DryRunHostDiscoverer(), statuses)
    results = engine.run()
    assert results[0].target_discovered is True
    assert results[0].target_ip is not None
