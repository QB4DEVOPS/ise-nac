#!/usr/bin/env python3
"""Build endpoints.csv and endpoints.yaml: 110 fake lab MACs.

CoS lock: 11 endpoint identity groups × 10 MACs = 110.
Not hardware. Not a 15k dump. No guest.

IEEE locally administered unicast: first-octet second hex digit is
2, 6, A, or E (LSB clear = unicast, next bit set = local). This
generator uses first octet 02 throughout.

Pattern: 02:00:GG:00:00:NN
  GG = group index 01..0B (Phones=01 … RFID_Readers=0B)
  NN = endpoint index 01..0A

Group names come from endpoint_identity_groups.yaml. Rebuild:
  python3 scripts/generate_endpoints.py
"""

from __future__ import annotations

import csv
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GROUPS_YAML = ROOT / "endpoint_identity_groups.yaml"
ENDPOINTS_CSV = ROOT / "endpoints.csv"
ENDPOINTS_YAML = ROOT / "endpoints.yaml"

LOCKED_GROUPS = (
    "Phones",
    "AP",
    "Printers",
    "TVs",
    "Badge_Readers",
    "Cameras",
    "UPS",
    "Powerstrips",
    "Linux",
    "Windows",
    "RFID_Readers",
)
MACS_PER_GROUP = 10
TARGET_COUNT = len(LOCKED_GROUPS) * MACS_PER_GROUP
REMOVED_GROUPS = ("Workstation", "IP-Phone", "Printer")
COLUMNS = ["mac", "endpoint_identity_group", "description"]
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
DESCRIPTION = "Lab MAC. Locally administered unicast (02). Not hardware."


def is_locally_administered_unicast(mac: str) -> bool:
    first = int(mac.split(":")[0], 16)
    return (first & 0x01) == 0 and (first & 0x02) == 0x02


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


def lab_mac(group_index: int, seq: int) -> str:
    # group_index 1..11, seq 1..10. First octet 02 = locally administered unicast.
    return f"02:00:{group_index:02x}:00:00:{seq:02x}"


def build(groups: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for gi, name in enumerate(groups, start=1):
        for seq in range(1, MACS_PER_GROUP + 1):
            rows.append(
                {
                    "mac": lab_mac(gi, seq),
                    "endpoint_identity_group": name,
                    "description": DESCRIPTION,
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
    per_group = Counter(r["endpoint_identity_group"] for r in rows)
    for name in groups:
        if per_group.get(name) != MACS_PER_GROUP:
            errors.append(f"{name} has {per_group.get(name)} MACs, want {MACS_PER_GROUP}")
    extra = set(per_group) - set(groups)
    if extra:
        errors.append(f"unknown groups in MAC list: {sorted(extra)}")
    for r in rows:
        mac = r["mac"]
        if not MAC_RE.fullmatch(mac):
            errors.append(f"MAC not lowercase colon hex: {mac}")
            break
        if not is_locally_administered_unicast(mac):
            errors.append(f"MAC is not locally administered unicast: {mac}")
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


def write_csv(rows: list[dict[str, str]]) -> None:
    with ENDPOINTS_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def write_yaml(rows: list[dict[str, str]]) -> None:
    lines = [
        "# Generated lab endpoints. Do not edit by hand.",
        "# Rebuild: python3 scripts/generate_endpoints.py",
        "# Fake MACs. Locally administered unicast (first octet 02). Not hardware.",
        "# 11 groups × 10 MACs = 110. No guest. No 15k dump.",
        "# CiscoDevNet/ise 0.3.4 ise_endpoint: name, mac, group_id,",
        "# static_group_assignment, static_profile_assignment.",
        "# https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/endpoint",
        "endpoints:",
    ]
    for r in rows:
        lines.append(f"  - mac: {r['mac']}")
        lines.append(f"    endpoint_identity_group: {r['endpoint_identity_group']}")
        lines.append(f"    description: {r['description']}")
    lines.append("")
    ENDPOINTS_YAML.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    groups = load_groups()
    rows = build(groups)
    verify(groups, rows)
    write_csv(rows)
    write_yaml(rows)
    print(f"wrote {ENDPOINTS_CSV} ({len(rows)} lab MACs)")
    print(f"wrote {ENDPOINTS_YAML}")
    print(f"groups={len(groups)} per_group={MACS_PER_GROUP} locally_administered_unicast=02")
    print(f"sample {rows[0]['endpoint_identity_group']} {rows[0]['mac']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
