# SPDX-License-Identifier: MIT
# Copyright (c) 2026-present Stable State Consulting Ltd.

"""Policy file schema (YAML) + validation.

This is the module everything else depends on, so it's built and tested
first. See policies/example.yaml for a fully worked example, and
docs in README.md for the schema reference.
"""
from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from vlanprobe.models import INTERNET_TARGET, Expectation

DEFAULT_PORTS = [22, 80, 443, 445, 3389]
DEFAULT_DHCP_TIMEOUT = 15
DEFAULT_INTERNET_TARGET = "1.1.1.1"
DEFAULT_INTERNET_PORT = 443


class PolicyError(Exception):
    """Raised for a malformed policy file. Carries a list of human-readable
    problems so the CLI can print all of them at once instead of one at a
    time."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


class StaticConfig(BaseModel):
    address: str  # CIDR, e.g. "10.0.10.5/24"
    gateway: str | None = None

    @field_validator("address")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_interface(v)
        except ValueError as exc:
            raise ValueError(f"not a valid CIDR address (e.g. 10.0.10.5/24): {exc}")
        return v

    @field_validator("gateway")
    @classmethod
    def _valid_gateway(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"not a valid IP address: {exc}")
        return v


class VlanConfig(BaseModel):
    id: int = Field(ge=1, le=4094)
    name: str
    dhcp: bool = True
    static: StaticConfig | None = None
    target_ip: str | None = None
    dhcp_timeout: int | None = None

    @field_validator("name")
    @classmethod
    def _name_not_reserved(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("vlan name cannot be empty")
        if v.strip().lower() == INTERNET_TARGET:
            raise ValueError(f"'{INTERNET_TARGET}' is a reserved name and cannot be used as a VLAN name")
        return v

    @field_validator("target_ip")
    @classmethod
    def _valid_target_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"not a valid IP address: {exc}")
        return v


class RuleConfig(BaseModel):
    from_: str = Field(alias="from")
    to: str
    expect: Expectation
    ports: list[int] | None = None

    model_config = {"populate_by_name": True}

    @field_validator("ports")
    @classmethod
    def _valid_ports(cls, v: list[int] | None) -> list[int] | None:
        if v is None:
            return v
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"port {p} is out of range 1-65535")
        return v

    @model_validator(mode="after")
    def _from_ne_to(self):
        if self.from_ == self.to:
            raise ValueError(f"rule 'from' and 'to' are both '{self.from_}' — a VLAN cannot be tested against itself")
        return self


class Defaults(BaseModel):
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS))
    dhcp_timeout: int = DEFAULT_DHCP_TIMEOUT
    internet_target: str = DEFAULT_INTERNET_TARGET
    internet_port: int = DEFAULT_INTERNET_PORT
    ping: bool = True

    @field_validator("internet_target")
    @classmethod
    def _valid_internet_target(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"internet_target must be a valid IP address: {exc}")
        return v


class DeviceConfig(BaseModel):
    trunk_interface: str | None = None


class Policy(BaseModel):
    device: DeviceConfig = Field(default_factory=DeviceConfig)
    vlans: list[VlanConfig]
    rules: list[RuleConfig]
    defaults: Defaults = Field(default_factory=Defaults)

    @model_validator(mode="after")
    def _cross_reference(self):
        errors: list[str] = []

        if not self.vlans:
            errors.append("policy must define at least one VLAN")

        ids_seen: dict[int, str] = {}
        names_seen: set[str] = set()
        for v in self.vlans:
            if v.id in ids_seen:
                errors.append(f"VLAN id {v.id} is used by both '{ids_seen[v.id]}' and '{v.name}'")
            else:
                ids_seen[v.id] = v.name
            if v.name in names_seen:
                errors.append(f"VLAN name '{v.name}' is defined more than once")
            names_seen.add(v.name)

        if not self.rules:
            errors.append("policy must define at least one rule")

        valid_targets = names_seen | {INTERNET_TARGET}
        for i, r in enumerate(self.rules):
            if r.from_ not in names_seen:
                errors.append(f"rule {i}: from '{r.from_}' is not a defined VLAN name")
            if r.from_ == INTERNET_TARGET:
                errors.append(f"rule {i}: '{INTERNET_TARGET}' cannot be used as a 'from' — tests originate from a VLAN sub-interface")
            if r.to not in valid_targets:
                errors.append(f"rule {i}: to '{r.to}' is not a defined VLAN name or '{INTERNET_TARGET}'")

        if errors:
            raise ValueError("; ".join(errors))
        return self

    def vlan_by_name(self, name: str) -> VlanConfig | None:
        for v in self.vlans:
            if v.name == name:
                return v
        return None

    def effective_ports(self, rule: RuleConfig) -> list[int]:
        return rule.ports if rule.ports is not None else list(self.defaults.ports)


def _read_yaml(path: Path) -> dict:
    try:
        raw = path.read_text()
    except OSError as exc:
        raise PolicyError([f"could not read policy file '{path}': {exc}"])
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyError([f"policy file is not valid YAML: {exc}"])
    if data is None:
        raise PolicyError(["policy file is empty"])
    if not isinstance(data, dict):
        raise PolicyError(["policy file must be a YAML mapping at the top level (vlans:, rules:, ...)"])
    return data


def load_policy(path: str | Path) -> Policy:
    """Parse and fully validate a policy file. Raises PolicyError with a
    list of all problems found if it's invalid."""
    path = Path(path)
    data = _read_yaml(path)
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        errors = []
        for e in exc.errors():
            loc = ".".join(str(p) for p in e["loc"])
            errors.append(f"{loc}: {e['msg']}" if loc else e["msg"])
        raise PolicyError(errors)


def hash_policy_file(path: str | Path) -> str:
    """SHA-256 of the raw policy file, for embedding in the report as
    evidence of exactly which policy version was tested."""
    path = Path(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest
