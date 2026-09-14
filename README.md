# VLANVerify

[www.vlanverify.com](https://www.vlanverify.com) · [GitHub](https://github.com/rosscooney/vlanverify)

VLANVerify verifies that VLAN network segmentation actually holds in
practice, instead of trusting the switch/firewall configuration alone.
It's built for small businesses and the IT consultants preparing them for
a Cyber Essentials / Cyber Essentials Plus audit, where an assessor wants
evidence that segmented network boundaries genuinely block traffic — not
just a network diagram that claims they do.

A single Linux device (a Raspberry Pi or similar) connects to a trunk
port on the switch. VLANVerify creates a tagged 802.1Q sub-interface for
every VLAN under test, so it can originate and receive traffic as if it
were a host on each VLAN in turn — without needing to be physically moved
between ports. It then tests actual reachability between VLANs against a
policy you define, and produces a plain-English pass/fail report.

## Status

MVP. Point-in-time, run-on-demand scans only. See [Roadmap /
non-goals](#roadmap--non-goals-for-this-mvp) below for what's deliberately
not built yet.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e .

# Check a policy file is well-formed, no network access required
.venv/bin/vlanverify validate --policy policies/example.yaml

# Try the full pipeline without touching real interfaces
.venv/bin/vlanverify scan --policy policies/example.yaml --interface eth0 \
    --output report.html --dry-run

# On the actual probe device, plugged into a trunk port, as root:
sudo vlanverify scan --policy policies/example.yaml --interface eth0 \
    --output report.html
```

Open `report.html` in a browser. It's a single self-contained file — no
external assets, safe to email or attach to an audit evidence pack.

## How it works

1. **Read the policy** (`policies/example.yaml`) — which VLANs exist and
   which pairwise reachability rules should hold between them.
2. **Bring up sub-interfaces** — for each VLAN, create a tagged
   sub-interface on the trunk NIC (`ip link add link eth0 name eth0.10
   type vlan id 10`), try DHCP, and fall back to a configured static
   address if DHCP is disabled or times out. A VLAN that gets no address
   at all is reported, not treated as a crash — that's often exactly the
   kind of finding an audit cares about.
3. **Run the tests** — for each rule, ping and TCP-connect from the
   `from` VLAN's sub-interface to a host on the `to` VLAN (a configured
   `target_ip`, or one found by a quick ping sweep), and record what
   actually happened.
4. **Compare against policy** — each rule gets a verdict:
   - `HELD` — actual behaviour matched what the policy expected.
   - `VIOLATED` — actual behaviour contradicted the policy. If a `deny`
     rule was actually reachable, that's a **security finding**: the
     VLAN boundary isn't enforced. If an `allow` rule was actually
     blocked, that's flagged too, but as a likely over-restrictive
     firewall rather than a segmentation failure.
   - `INCONCLUSIVE` — couldn't be tested (e.g. no live host found on the
     target VLAN, or the source VLAN never got an address).
5. **Report** — a single HTML file: a plain-English summary up top, a red
   banner for any security findings, a results table per rule, and an
   expandable "technical details" section per rule for the raw
   ping/port data.

## Policy file schema

```yaml
device:
  trunk_interface: eth0        # optional; can also be passed as --interface

vlans:
  - id: 10                     # 802.1Q VLAN tag, 1-4094
    name: corp                 # used to refer to this VLAN in rules — must be unique
    dhcp: true                 # default true; try DHCP on this sub-interface first
    static:                    # fallback (or override, if dhcp: false) static config
      address: 10.0.10.5/24
      gateway: 10.0.10.1
    target_ip: 10.0.10.50      # known-good host to test against; if omitted,
                                # VLANVerify ping-sweeps the subnet to find one
    dhcp_timeout: 15           # optional per-VLAN override of defaults.dhcp_timeout

rules:
  - from: guest                # must be a VLAN name (not "internet")
    to: corp                   # a VLAN name, or the special value "internet"
    expect: deny                # allow | deny
    ports: [22, 443]           # optional; defaults to defaults.ports

  - from: guest
    to: internet                # special target: reachability to defaults.internet_target
    expect: allow

defaults:
  ports: [22, 80, 443, 445, 3389]   # used when a rule has no ports: of its own
  dhcp_timeout: 15                   # seconds to wait for DHCP before falling back
  internet_target: 1.1.1.1
  internet_port: 443
  ping: true                         # also ICMP ping alongside the TCP port checks
```

Run `vlanverify validate --policy your.yaml` to check a file against this
schema — it reports every problem found, not just the first.

## CLI reference

```
vlanverify validate --policy policy.yaml
vlanverify scan --policy policy.yaml --interface eth0 --output report.html [OPTIONS]
```

`scan` options:

| Flag | Description |
|---|---|
| `--dry-run` | Don't touch real interfaces or send real traffic. Logs what it would do and uses simulated (worst-case: everything reachable) probe results. Useful for development and for demoing the report without hardware. |
| `--keep-interfaces` | Don't delete the VLAN sub-interfaces after the scan. Useful for debugging on real hardware. |
| `-v`, `--verbose` | Verbose logging. |

**Exit codes:** `0` — scan completed, no security findings. `2` — scan
completed, at least one `deny` rule was violated (see the report). `1` —
the tool itself failed (bad policy, missing interface, etc). This makes
it straightforward to wire into a script or CI check.

## Requirements

- Linux (Raspberry Pi OS / Debian) for a live scan — it shells out to
  `ip` (iproute2) and a DHCP client (`dhclient` or `dhcpcd`), and uses
  `SO_BINDTODEVICE` to bind test traffic to the correct VLAN
  sub-interface. `--dry-run` mode works on any OS with Python 3.10+.
- Run as root, or with `CAP_NET_ADMIN` at minimum, since creating VLAN
  sub-interfaces requires it.
- Python 3.10+, and the dependencies in `pyproject.toml` (PyYAML,
  pydantic, Jinja2, Click) — no other runtime dependencies, no cloud
  calls, no telemetry, beyond the one deliberate internet-reachability
  test target.

## Project layout

```
vlanverify/
  models.py       # shared dataclasses/enums (no other module dependencies)
  schema.py       # policy YAML parsing + validation (pydantic)
  interfaces.py   # VLAN sub-interface orchestration: Real + DryRun backends
  discovery.py     # live host discovery (ping sweep / ARP): Real + DryRun backends
  testengine.py    # ping/TCP probing + rule verdict logic: Real + Mock backends
  report.py         # ScanReport -> self-contained HTML
  templates/
    report.html.j2
  cli.py             # `vlanverify validate` / `vlanverify scan`
policies/
  example.yaml
tests/
```

Every layer that touches the outside world (`interfaces.py`,
`discovery.py`, `testengine.py`) is split into an abstract base plus a
`Real*` and a `Dry*`/`Mock*` implementation. `cli.py` picks which pair to
use based on `--dry-run`. This is what makes `--dry-run` possible without
duplicating logic, and it's also the seam for the two modes described
below.

## Roadmap / non-goals for this MVP

Deliberately not built yet, but the architecture leaves room for them
without a rewrite:

- **Config-only audit mode** — read firewall/switch ACL exports instead
  of live-testing traffic. This would be a new backend for the same
  `Prober`/verdict logic in `testengine.py`, not a new tool.
- **Multi-agent mode** — one small device per VLAN instead of 802.1Q
  trunk tagging from a single device. `InterfaceManager` already
  abstracts "how does the probe get an address on VLAN X" from
  everything downstream, so this is a third `InterfaceManager`
  implementation, not a redesign.
- Continuous/scheduled scanning (this is point-in-time, run-on-demand
  only for now).
- Firewall/switch config ingestion and diffing against live results.
- Any GUI beyond the generated HTML report.
- Cloud-native segmentation (AWS/Azure security groups, k8s network
  policies).

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The test suite runs entirely against the dry-run/mock backends, so it
needs no root privileges, no Linux, and no real network — it's exercising
the schema validation, verdict logic, and report rendering, which is
where the actual bugs live.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026-present Stable State
Consulting Ltd.
