#!/usr/bin/env python3
"""Build endpoints.csv and endpoints.yaml: 110 lab MACs with real IEEE OUIs.

CoS lock: 11 endpoint identity groups × 10 MACs = 110.
Not hardware. Not a 15k dump. No guest. Drop the 02:00:GG pattern.

Pattern: {IEEE MA-L OUI}:{generated last 3 octets}

OUI source of truth (MA-L): https://standards-oui.ieee.org/oui/oui.txt
Locked mapping (do not invent others). Last 3 octets are hashed lab
suffixes — unique across 110, not 00:00:01–00:00:0A, not a sequential
counter in the last octet with zeros in the middle, not copied from a NIC.

Group names come from endpoint_identity_groups.yaml. Rebuild:
  python3 scripts/generate_endpoints.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GROUPS_YAML = ROOT / "endpoint_identity_groups.yaml"
ENDPOINTS_CSV = ROOT / "endpoints.csv"
ENDPOINTS_YAML = ROOT / "endpoints.yaml"

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
IEEE_HEX_RE = re.compile(
    r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$"
)

# Locked CoS mapping. Keys must match endpoint_identity_groups.yaml order.
# OUI is colon-hex lowercase. locked_org is the CoS name to verify against
# the IEEE MA-L (hex) organization string — never swap if IEEE disagrees.
LOCKED_OUI = {
    "Phones": ("00:04:f2", "Polycom"),
    "AP": ("9c:e3:30", "Cisco Meraki"),
    "Printers": ("9c:7b:ef", "Hewlett Packard"),
    "TVs": ("64:1b:2f", "Samsung Electronics"),
    "Badge_Readers": ("00:30:8e", "HID Global"),
    "Cameras": ("00:40:8c", "Axis Communications"),
    "UPS": ("00:c0:b7", "APC"),
    "Powerstrips": ("00:0d:5d", "Raritan"),
    "Linux": ("00:c0:4f", "Dell"),
    "Windows": ("10:e7:c6", "Hewlett Packard"),
    "RFID_Readers": ("00:16:25", "Impinj"),
}
# IEEE legal names that do not contain the CoS short name as a substring.
ORG_ALIASES = {
    "apc": ("american power conversion",),
}

LOCKED_GROUPS = tuple(LOCKED_OUI)
MACS_PER_GROUP = 10
TARGET_COUNT = len(LOCKED_GROUPS) * MACS_PER_GROUP
REMOVED_GROUPS = ("Workstation", "IP-Phone", "Printer")
COLUMNS = ["mac", "endpoint_identity_group", "oui", "organization", "description"]
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
# Documented lab salt (not a secret). Changes the suffix stream; do not copy NICs.
LAB_SALT = "ise-nac-lab-ieee-mal-v1"
TRIVIAL_LAST = {f"00:00:{n:02x}" for n in range(1, 11)}


def load_groups() -> list[str]:
    raw = yaml.safe_load(GROUPS_YAML.read_text(encoding="utf-8")) or {}
    rows = raw.get("endpoint_identity_groups") or []
    names = [str(r["name"]) for r in rows if isinstance(r, dict) and r.get("name")]
    if tuple(names) != LOCKED_GROUPS:
        raise SystemExit(
            f"endpoint_identity_groups.yaml must be exactly {list(LOCKED_GROUPS)}, got {names}"
        )
    if any(n in REMOVED_GROUPS for n in names):
        raise SystemExit("Workstation / IP-Phone / Printer groups are gone; use the CoS lock names")
    if any("guest" in n.lower() for n in names):
        raise SystemExit("Guest endpoint identity groups are not in this phase")
    return names


def fetch_ieee_oui_text() -> str:
    override = os.environ.get("IEEE_OUI_TXT")
    if override:
        path = Path(override)
        if not path.is_file():
            raise SystemExit(f"IEEE_OUI_TXT={override} is not a file")
        return path.read_text(encoding="utf-8", errors="replace")
    last_err: Exception | None = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(
                IEEE_OUI_URL,
                headers={"User-Agent": "ise-nac-lab-oui-verify/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
            if attempt == 3:
                break
    raise SystemExit(
        f"failed to download IEEE MA-L registry {IEEE_OUI_URL}: {last_err}"
    )


def parse_ieee_mal(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in text.splitlines():
        m = IEEE_HEX_RE.match(line)
        if not m:
            continue
        oui = m.group(1).lower().replace("-", ":")
        mapping[oui] = m.group(2).strip()
    if not mapping:
        raise SystemExit("IEEE MA-L file parsed to zero (hex) assignments")
    return mapping


def org_matches(locked_org: str, ieee_org: str) -> bool:
    lock = locked_org.casefold().strip()
    ieee = ieee_org.casefold().strip()
    if lock in ieee or ieee in lock:
        return True
    return any(alias in ieee for alias in ORG_ALIASES.get(lock, ()))


def verify_locked_ouis(ieee: dict[str, str]) -> dict[str, str]:
    """Return group -> IEEE organization. Stop on missing OUI or org mismatch."""
    ieee_org_by_group: dict[str, str] = {}
    failures: list[str] = []
    for group, (oui, locked_org) in LOCKED_OUI.items():
        ieee_org = ieee.get(oui)
        if ieee_org is None:
            failures.append(
                f"{group} OUI {oui.upper()} is missing from IEEE MA-L {IEEE_OUI_URL}. "
                "Stopping. Do not invent or swap OUIs."
            )
            continue
        if not org_matches(locked_org, ieee_org):
            failures.append(
                f"{group} OUI {oui.upper()} org does not match IEEE MA-L. "
                f"locked={locked_org!r} ieee={ieee_org!r}. "
                "Stopping. Do not invent or swap OUIs."
            )
            continue
        ieee_org_by_group[group] = ieee_org
    if failures:
        raise SystemExit("IEEE MA-L verification failed:\n  " + "\n  ".join(failures))
    return ieee_org_by_group


def is_trivial_nic_suffix(suffix: str) -> bool:
    """Reject suffixes that look like a toy counter or a first-NIC default."""
    parts = suffix.split(":")
    if len(parts) != 3:
        return True
    a, b, c = (int(p, 16) for p in parts)
    if suffix in TRIVIAL_LAST:
        return True
    if a == 0 and b == 0:
        return True
    if b == 0 and 1 <= c <= 10:
        return True
    if suffix in {"00:00:00", "ff:ff:ff"}:
        return True
    return False


def nic_suffix(group: str, seq: int, used: set[str]) -> str:
    """Deterministic 24-bit lab suffix from SHA-256. Not copied from hardware."""
    n = 0
    while n < 4096:
        digest = hashlib.sha256(f"{LAB_SALT}|{group}|{seq}|{n}".encode("utf-8")).digest()
        suffix = ":".join(f"{b:02x}" for b in digest[:3])
        if suffix not in used and not is_trivial_nic_suffix(suffix):
            used.add(suffix)
            return suffix
        n += 1
    raise SystemExit(f"could not allocate a non-trivial NIC suffix for {group} seq={seq}")


def description_for(oui: str, ieee_org: str) -> str:
    return (
        f"Lab MAC. Not hardware. IEEE MA-L OUI {oui.upper()} ({ieee_org}). "
        "Last 3 octets generated; not copied from a device."
    )


def build(groups: list[str], ieee_org_by_group: dict[str, str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    used_suffixes: set[str] = set()
    for name in groups:
        oui, _locked_org = LOCKED_OUI[name]
        ieee_org = ieee_org_by_group[name]
        for seq in range(1, MACS_PER_GROUP + 1):
            suffix = nic_suffix(name, seq, used_suffixes)
            mac = f"{oui}:{suffix}"
            rows.append(
                {
                    "mac": mac,
                    "endpoint_identity_group": name,
                    "oui": oui,
                    "organization": ieee_org,
                    "description": description_for(oui, ieee_org),
                }
            )
    return rows


def verify(groups: list[str], rows: list[dict[str, str]]) -> None:
    errors: list[str] = []
    if len(rows) != TARGET_COUNT:
        errors.append(f"row count {len(rows)} != {TARGET_COUNT}")
    macs = [r["mac"] for r in rows]
    if len(macs) != len(set(macs)):
        dup = [m for m, c in Counter(macs).items() if c > 1]
        errors.append(f"duplicate MACs: {dup[:5]}")
    suffixes = [":".join(m.split(":")[3:]) for m in macs]
    if len(suffixes) != len(set(suffixes)):
        errors.append("last-3-octet suffixes must be unique across 110")
    per_group = Counter(r["endpoint_identity_group"] for r in rows)
    for name in groups:
        if per_group.get(name) != MACS_PER_GROUP:
            errors.append(f"{name} has {per_group.get(name)} MACs, want {MACS_PER_GROUP}")
    extra = set(per_group) - set(groups)
    if extra:
        errors.append(f"unknown groups in MAC list: {sorted(extra)}")
    for r in rows:
        mac = r["mac"]
        group = r["endpoint_identity_group"]
        oui, _locked = LOCKED_OUI[group]
        if not MAC_RE.fullmatch(mac):
            errors.append(f"MAC not lowercase colon hex: {mac}")
            break
        if mac.startswith("02:00:"):
            errors.append(f"dropped 02:00:GG pattern still present: {mac}")
            break
        if not mac.startswith(f"{oui}:"):
            errors.append(f"{group} MAC {mac} does not start with locked OUI {oui}")
            break
        if r["oui"] != oui:
            errors.append(f"{group} csv oui {r['oui']} != locked {oui}")
            break
        suffix = ":".join(mac.split(":")[3:])
        if is_trivial_nic_suffix(suffix):
            errors.append(f"trivial NIC suffix: {mac}")
            break
        desc = r["description"].casefold()
        if "lab" not in desc or "not hardware" not in desc:
            errors.append(f"description must say lab / not hardware: {mac}")
            break
        if mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            errors.append(f"banned MAC: {mac}")
    blob = ",".join(macs).lower()
    if "guest" in blob:
        errors.append("guest appears in MAC list")
    if TARGET_COUNT >= 15000 or len(rows) >= 15000:
        errors.append("do not dump 15k MACs")
    if errors:
        raise SystemExit("verification failed:\n  " + "\n  ".join(errors))


def yaml_scalar(value: str) -> str:
    if (
        value.lower() in {"true", "false", "null", "yes", "no", "on", "off", "y", "n"}
        or value[0] in "-?:{}[],&*!|>%@`'\""
        or any(c in value for c in ":#{}[],&*!|>%@`'\"\\")
        or value.strip() != value
    ):
        return json.dumps(value, ensure_ascii=False)
    return value


def write_csv(rows: list[dict[str, str]]) -> None:
    with ENDPOINTS_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def write_yaml(rows: list[dict[str, str]]) -> None:
    lines = [
        "# Generated lab endpoints. Do not edit by hand.",
        "# Rebuild: python3 scripts/generate_endpoints.py",
        "# Lab MACs. Not hardware. Not copied from a device. No guest. No 15k dump.",
        "# Pattern: {IEEE MA-L OUI}:{generated last 3 octets}. Drop 02:00:GG.",
        f"# IEEE MA-L source: {IEEE_OUI_URL}",
        "# 11 groups × 10 MACs = 110. Last 3 octets hashed, unique, not 00:00:01–0A.",
        "# CiscoDevNet/ise 0.3.4 ise_endpoint: name, mac, group_id,",
        "# static_group_assignment, static_profile_assignment.",
        "# https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/endpoint",
        "endpoints:",
    ]
    for r in rows:
        lines.append(f"  - mac: {r['mac']}")
        lines.append(f"    endpoint_identity_group: {r['endpoint_identity_group']}")
        lines.append(f"    oui: {r['oui']}")
        lines.append(f"    organization: {yaml_scalar(r['organization'])}")
        lines.append(f"    description: {yaml_scalar(r['description'])}")
    lines.append("")
    ENDPOINTS_YAML.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    groups = load_groups()
    ieee = parse_ieee_mal(fetch_ieee_oui_text())
    ieee_org_by_group = verify_locked_ouis(ieee)
    rows = build(groups, ieee_org_by_group)
    verify(groups, rows)
    write_csv(rows)
    write_yaml(rows)
    print(f"wrote {ENDPOINTS_CSV} ({len(rows)} lab MACs)")
    print(f"wrote {ENDPOINTS_YAML}")
    print(f"groups={len(groups)} per_group={MACS_PER_GROUP} ieee_mal={IEEE_OUI_URL}")
    for group, (oui, locked_org) in LOCKED_OUI.items():
        print(f"  {group} {oui} locked={locked_org!r} ieee={ieee_org_by_group[group]!r}")
    print(f"sample {rows[0]['endpoint_identity_group']} {rows[0]['mac']}")
    print(f"last   {rows[-1]['endpoint_identity_group']} {rows[-1]['mac']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
