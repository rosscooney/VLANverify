# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

"""Command-line entry point.

  vlanprobe validate --policy policy.yaml
  vlanprobe scan --policy policy.yaml --interface eth0 --output report.html [--dry-run]
"""
from __future__ import annotations

import logging
import sys

import click

from vlanprobe.discovery import DryRunHostDiscoverer, RealHostDiscoverer
from vlanprobe.interfaces import build_interface_manager
from vlanprobe.models import Verdict
from vlanprobe.report import build_report, write_report
from vlanprobe.schema import Policy, PolicyError, load_policy
from vlanprobe.testengine import MockProber, RealProber, TestEngine

log = logging.getLogger("vlanprobe")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s" if verbose else "%(message)s",
    )


@click.group()
def main():
    """VLANProbe — verify that VLAN network isolation actually holds in practice."""


@main.command()
@click.option("--policy", "policy_path", required=True, type=click.Path(exists=True, dir_okay=False),
              help="Path to the policy YAML file.")
def validate(policy_path: str):
    """Check that a policy file is well-formed. Does not touch the network."""
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        click.secho(f"✗ {policy_path} is invalid:", fg="red", bold=True)
        for err in exc.errors:
            click.echo(f"  - {err}")
        sys.exit(1)

    click.secho(f"✓ {policy_path} is valid", fg="green", bold=True)
    click.echo(f"  {len(policy.vlans)} VLAN(s): {', '.join(f'{v.name}({v.id})' for v in policy.vlans)}")
    click.echo(f"  {len(policy.rules)} rule(s)")
    for r in policy.rules:
        ports = policy.effective_ports(r) if r.to != "internet" else [policy.defaults.internet_port]
        click.echo(f"    {r.from_} -> {r.to}: expect {r.expect.value} (ports: {', '.join(map(str, ports))})")


@main.command()
@click.option("--policy", "policy_path", required=True, type=click.Path(exists=True, dir_okay=False),
              help="Path to the policy YAML file.")
@click.option("--interface", "interface", default=None,
              help="Trunk NIC to create VLAN sub-interfaces on (overrides device.trunk_interface in the policy).")
@click.option("--output", "output_path", default="report.html", type=click.Path(dir_okay=False),
              help="Where to write the HTML report. Default: report.html")
@click.option("--dry-run", is_flag=True, default=False,
              help="Don't touch real interfaces or send real traffic — log what would happen and use simulated results.")
@click.option("--keep-interfaces", is_flag=True, default=False,
              help="Don't delete the VLAN sub-interfaces after the scan (useful for debugging).")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose logging.")
def scan(policy_path: str, interface: str | None, output_path: str, dry_run: bool,
          keep_interfaces: bool, verbose: bool):
    """Run a live (or dry-run) VLAN isolation scan and produce an HTML report."""
    _setup_logging(verbose)

    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        click.secho(f"✗ {policy_path} is invalid:", fg="red", bold=True)
        for err in exc.errors:
            click.echo(f"  - {err}")
        sys.exit(1)

    trunk_interface = interface or policy.device.trunk_interface
    if not trunk_interface:
        click.secho("✗ No trunk interface given. Pass --interface or set device.trunk_interface in the policy.",
                    fg="red", bold=True)
        sys.exit(1)

    if not dry_run and sys.platform != "linux":
        click.secho(f"✗ Live scanning requires Linux (uses `ip link`, SO_BINDTODEVICE). "
                    f"Detected: {sys.platform}. Use --dry-run to test the pipeline here instead.",
                    fg="red", bold=True)
        sys.exit(1)

    mode = "DRY RUN" if dry_run else "LIVE"
    click.secho(f"VLANProbe scan [{mode}] — trunk interface {trunk_interface}", bold=True)

    ifmgr = build_interface_manager(dry_run, trunk_interface, policy.defaults.dhcp_timeout)
    prober = MockProber() if dry_run else RealProber()
    discoverer = DryRunHostDiscoverer() if dry_run else RealHostDiscoverer()

    interface_statuses = ifmgr.setup(policy.vlans)
    for status in interface_statuses.values():
        if status.usable:
            click.echo(f"  {status.vlan_name} ({status.ifname}): {status.method.value} -> {status.address}")
        else:
            click.secho(f"  {status.vlan_name} ({status.ifname}): no address — {status.error}", fg="yellow")

    try:
        engine = TestEngine(policy, prober, discoverer, interface_statuses)
        rule_results = engine.run()
    finally:
        if not keep_interfaces:
            ifmgr.teardown()

    report = build_report(policy, policy_path, trunk_interface, dry_run, interface_statuses, rule_results)
    out = write_report(report, output_path)

    counts = report.summary_counts
    click.echo()
    click.secho(f"Held: {counts['HELD']}  Violated: {counts['VIOLATED']}  Inconclusive: {counts['INCONCLUSIVE']}",
                bold=True)
    security_violations = [r for r in rule_results if r.is_security_violation]
    if security_violations:
        click.secho(f"⚠ {len(security_violations)} VLAN boundary violation(s) found — see {out}", fg="red", bold=True)
    click.echo(f"Report written to {out}")

    if security_violations:
        sys.exit(2)


if __name__ == "__main__":
    main()
