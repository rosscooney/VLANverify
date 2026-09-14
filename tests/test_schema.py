# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

import textwrap

import pytest

from vlanprobe.schema import PolicyError, load_policy


def write_policy(tmp_path, content: str):
    path = tmp_path / "policy.yaml"
    path.write_text(textwrap.dedent(content))
    return path


def test_valid_example_policy_loads():
    policy = load_policy("policies/example.yaml")
    assert {v.name for v in policy.vlans} == {"corp", "guest", "iot"}
    assert len(policy.rules) == 5


def test_default_ports_applied_when_rule_omits_them():
    policy = load_policy("policies/example.yaml")
    rule = next(r for r in policy.rules if r.from_ == "guest" and r.to == "corp")
    assert policy.effective_ports(rule) == [22, 80, 443, 445, 3389]


def test_rule_specific_ports_override_defaults():
    policy = load_policy("policies/example.yaml")
    rule = next(r for r in policy.rules if r.from_ == "corp" and r.to == "iot")
    assert policy.effective_ports(rule) == [22, 443]


def test_duplicate_vlan_id_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a}
          - {id: 10, name: b}
        rules:
          - {from: a, to: b, expect: deny}
    """)
    with pytest.raises(PolicyError) as exc:
        load_policy(path)
    assert any("id 10" in e for e in exc.value.errors)


def test_duplicate_vlan_name_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a}
          - {id: 20, name: a}
        rules:
          - {from: a, to: a, expect: deny}
    """)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_rule_referencing_unknown_vlan_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a}
        rules:
          - {from: a, to: doesnotexist, expect: deny}
    """)
    with pytest.raises(PolicyError) as exc:
        load_policy(path)
    assert any("doesnotexist" in e for e in exc.value.errors)


def test_reserved_internet_name_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: internet}
        rules:
          - {from: internet, to: internet, expect: allow}
    """)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_rule_from_equals_to_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a}
        rules:
          - {from: a, to: a, expect: deny}
    """)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_port_out_of_range_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a}
          - {id: 20, name: b}
        rules:
          - {from: a, to: b, expect: allow, ports: [70000]}
    """)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_internet_as_rule_to_is_allowed(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a}
        rules:
          - {from: a, to: internet, expect: allow}
    """)
    policy = load_policy(path)
    assert policy.rules[0].to == "internet"


def test_internet_as_rule_from_is_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a}
        rules:
          - {from: internet, to: a, expect: allow}
    """)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_empty_policy_file_rejected(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_invalid_yaml_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("vlans: [this is not: valid: yaml")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_invalid_static_cidr_rejected(tmp_path):
    path = write_policy(tmp_path, """
        vlans:
          - {id: 10, name: a, static: {address: "not-an-ip"}}
          - {id: 20, name: b}
        rules:
          - {from: a, to: b, expect: allow}
    """)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_missing_file_raises_policy_error(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.yaml")
