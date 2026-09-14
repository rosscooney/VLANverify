# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.1] - 2026-09-14

### Changed
- Renamed the project from VLANProbe to VLANVerify (package, CLI command,
  and all documentation). No functional changes.

## [0.1.0] - 2026-09-14

Initial MVP.

### Added
- YAML policy file schema (VLANs, pairwise `allow`/`deny` rules, optional
  per-rule ports, the special `internet` target) with full validation via
  `vlanverify validate`.
- VLAN 802.1Q sub-interface orchestration on Linux (`ip link`), with DHCP
  first and a configurable static-IP fallback per VLAN.
- `--dry-run` mode: logs every action it would take and fabricates
  plausible results, so the pipeline can be developed and tested without
  root or a real trunk port.
- Test engine: ICMP ping + TCP connect checks per rule, with live-host
  auto-discovery (ping sweep / neighbour table) when no `target_ip` is
  configured, and `HELD` / `VIOLATED` / `INCONCLUSIVE` verdicts.
- Self-contained single-file HTML report: plain-English summary, a
  critical-findings banner for VLAN boundaries that don't hold, a
  per-rule results table, and an expandable technical-details section per
  rule.
- `vlanverify scan` and `vlanverify validate` CLI commands.
- Test suite covering the schema, interface orchestration, test engine
  verdict logic, and report rendering (all against dry-run/mock
  backends).
