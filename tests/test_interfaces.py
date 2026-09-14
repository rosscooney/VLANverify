# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

from vlanprobe.interfaces import DryRunInterfaceManager, subif_name
from vlanprobe.models import IPAssignMethod
from vlanprobe.schema import StaticConfig, VlanConfig


def test_subif_name_format():
    assert subif_name("eth0", 10) == "eth0.10"


def test_dry_run_dhcp_vlan_gets_fabricated_address():
    mgr = DryRunInterfaceManager("eth0", dhcp_timeout_default=15)
    vlan = VlanConfig(id=10, name="corp", dhcp=True)
    statuses = mgr.setup([vlan])
    status = statuses["corp"]
    assert status.method == IPAssignMethod.DHCP
    assert status.address is not None
    assert status.usable
    assert status.ifname == "eth0.10"


def test_dry_run_static_fallback_used_when_dhcp_disabled():
    mgr = DryRunInterfaceManager("eth0", dhcp_timeout_default=15)
    vlan = VlanConfig(id=30, name="iot", dhcp=False, static=StaticConfig(address="10.0.30.5/24"))
    statuses = mgr.setup([vlan])
    status = statuses["iot"]
    assert status.method == IPAssignMethod.STATIC
    assert status.address == "10.0.30.5/24"
    assert status.usable


def test_dry_run_no_dhcp_no_static_is_reported_not_crashed():
    mgr = DryRunInterfaceManager("eth0", dhcp_timeout_default=15)
    vlan = VlanConfig(id=40, name="isolated", dhcp=False, static=None)
    statuses = mgr.setup([vlan])
    status = statuses["isolated"]
    assert status.method == IPAssignMethod.NONE
    assert not status.usable
    assert status.error


def test_dry_run_teardown_logs_deletion_for_every_created_interface():
    mgr = DryRunInterfaceManager("eth0", dhcp_timeout_default=15)
    vlans = [VlanConfig(id=i, name=f"vlan{i}", dhcp=True) for i in (10, 20, 30)]
    mgr.setup(vlans)
    mgr.teardown()
    delete_actions = [a.description for a in mgr.actions if "delete" in a.description]
    assert len(delete_actions) == 3
    assert mgr._created == []


def test_dry_run_never_shells_out(monkeypatch):
    """The whole point of dry-run is that it's safe to run without root or
    a real trunk port — assert it never touches subprocess."""
    import subprocess as sp

    def boom(*args, **kwargs):
        raise AssertionError("dry-run must not call subprocess")

    monkeypatch.setattr(sp, "run", boom)
    mgr = DryRunInterfaceManager("eth0", dhcp_timeout_default=15)
    vlan = VlanConfig(id=10, name="corp", dhcp=True)
    mgr.setup([vlan])
    mgr.teardown()
