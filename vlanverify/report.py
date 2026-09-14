# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

"""Renders a ScanReport as a single self-contained HTML file.

Kept deliberately dumb: this module just gathers data into a ScanReport
and hands it to a Jinja2 template (templates/report.html.j2). All the
"how do we phrase this for a non-technical reader" decisions live in the
template, not here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vlanverify.models import InterfaceStatus, RuleResult, ScanReport, Verdict
from vlanverify.schema import Policy, hash_policy_file

TEMPLATE_DIR = Path(__file__).parent / "templates"


def build_report(policy: Policy, policy_path: str, device_interface: str, dry_run: bool,
                  interface_statuses: dict[str, InterfaceStatus], rule_results: list[RuleResult]) -> ScanReport:
    return ScanReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        device_interface=device_interface,
        policy_path=str(policy_path),
        policy_hash=hash_policy_file(policy_path),
        dry_run=dry_run,
        interface_statuses=list(interface_statuses.values()),
        rule_results=rule_results,
    )


def render_html(report: ScanReport) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    counts = report.summary_counts
    security_violations = [r for r in report.rule_results if r.is_security_violation]
    other_violations = [r for r in report.rule_results if r.verdict == Verdict.VIOLATED and not r.is_security_violation]
    return template.render(
        report=report,
        counts=counts,
        total=len(report.rule_results),
        security_violations=security_violations,
        other_violations=other_violations,
        Verdict=Verdict,
    )


def write_report(report: ScanReport, output_path: str | Path) -> Path:
    html = render_html(report)
    path = Path(output_path)
    path.write_text(html)
    return path
