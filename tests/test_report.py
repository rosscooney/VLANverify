# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

from vlanverify.models import (
    Expectation,
    IPAssignMethod,
    InterfaceStatus,
    ProbeOutcome,
    ProbeResult,
    RuleResult,
    Verdict,
)
from vlanverify.report import build_report, render_html
from vlanverify.schema import load_policy


def make_rule_result(from_v, to_v, expect, verdict, reachable=True):
    r = RuleResult(rule_index=0, from_vlan=from_v, to_vlan=to_v, expect=expect, target_ip="10.0.0.5")
    outcome = ProbeOutcome.REACHABLE if reachable else ProbeOutcome.UNREACHABLE
    r.probes.append(ProbeResult("ping", None, outcome))
    r.verdict = verdict
    r.notes = "test note"
    return r


def test_report_renders_summary_counts():
    policy = load_policy("policies/example.yaml")
    statuses = {
        "corp": InterfaceStatus(10, "corp", "eth0.10", IPAssignMethod.DHCP, address="10.0.10.5/24"),
    }
    results = [
        make_rule_result("guest", "corp", Expectation.DENY, Verdict.VIOLATED, reachable=True),
        make_rule_result("corp", "iot", Expectation.ALLOW, Verdict.HELD, reachable=True),
        make_rule_result("iot", "corp", Expectation.DENY, Verdict.INCONCLUSIVE, reachable=False),
    ]
    report = build_report(policy, "policies/example.yaml", "eth0", dry_run=True,
                           interface_statuses=statuses, rule_results=results)
    html = render_html(report)

    assert "VLANVerify Report" in html
    assert 'DRY RUN' in html
    assert '<span class="num">3</span>' in html  # total rules tested
    assert '<span class="num">1</span>' in html  # each of held/violated/inconclusive is 1
    assert "VIOLATED" in html
    assert "HELD" in html
    assert "INCONCLUSIVE" in html
    assert "critical finding" in html


def test_report_shows_clean_banner_when_no_security_violations():
    policy = load_policy("policies/example.yaml")
    results = [
        make_rule_result("corp", "iot", Expectation.ALLOW, Verdict.HELD, reachable=True),
    ]
    report = build_report(policy, "policies/example.yaml", "eth0", dry_run=False,
                           interface_statuses={}, rule_results=results)
    html = render_html(report)
    assert "No critical findings" in html


def test_report_embeds_policy_hash():
    policy = load_policy("policies/example.yaml")
    report = build_report(policy, "policies/example.yaml", "eth0", dry_run=True,
                           interface_statuses={}, rule_results=[])
    html = render_html(report)
    assert report.policy_hash in html
    assert len(report.policy_hash) == 64  # sha256 hex digest
