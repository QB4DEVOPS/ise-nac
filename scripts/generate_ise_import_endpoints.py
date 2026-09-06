#!/usr/bin/env python3
"""Convert endpoints_enterprise.csv into ISE GUI/CSV import schema.

NDO / CoS lock (Robert 2026-09-06):
  New file only. Does not replace endpoints_enterprise.csv (Terraform apply
  path), lab endpoints.csv (110), Terraform, or the enterprise generator.
  ISE Context Visibility / inventory-export style. Do not apply this file
  together with endpoints_enterprise.csv and the lab 110 on a Small PAN.

Rebuild:
  python3 scripts/generate_ise_import_endpoints.py
Verify only (no write):
  python3 scripts/generate_ise_import_endpoints.py --verify
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE_CSV = ROOT / "endpoints_enterprise.csv"
LAB_ENDPOINTS_CSV = ROOT / "endpoints.csv"
ISE_IMPORT_CSV = ROOT / "endpoints_ise_import.csv"

TARGET_COUNT = 150000
DESCRIPTION = "'Generated. Not hardware. IEEE MA-L.'"

HEADER = [
    "MACAddress",
    "EndPointPolicy",
    "IdentityGroup",
    "Description",
    "DeviceRegistrationStatus",
    "BYODRegistration",
    "Device Type",
    "EmailAddress",
    "ip",
    "FirstName",
    "host-name",
    "LastName",
    "MDMServerID",
    "MDMServerName",
    "MDMEnrolled",
    "Location",
    "PortalUser",
    "User-Name",
    "StaticAssignment",
    "StaticGroupAssignment",
    "MDMOSVersion",
    "PortalUser.FirstName",
    "PortalUser.LastName",
    "PortalUser.EmailAddress",
    "PortalUser.PhoneNumber",
    "PortalUser.GuestType",
    "PortalUser.GuestStatus",
    "PortalUser.Location",
    "PortalUser.GuestSponsor",
    "PortalUser.CreationType",
    "AUPAccepted",
]

GROUP_COUNTS = {
    "Phones": 71000,
    "Windows": 71000,
    "AP": 2250,
    "Printers": 1550,
    "Cameras": 1500,
    "Badge_Readers": 800,
    "TVs": 600,
    "Linux": 500,
    "UPS": 400,
    "Powerstrips": 250,
    "RFID_Readers": 150,
}

POLICY_BY_GROUP = {
    "Phones": "Polycom-Device",
    "Windows": "HP-Device",
    "AP": "Meraki-Device",
    "Printers": "HP-Device",
    "Cameras": "Axis-Device",
    "Badge_Readers": "HID-Device",
    "TVs": "Samsung-Device",
    "Linux": "Dell-Device",
    "UPS": "APC-Device",
    "Powerstrips": "Raritan-Device",
    "RFID_Readers": "Impinj-Device",
}

LOCKED_OUI = {
    "Phones": "00:04:F2",
    "Windows": "10:E7:C6",
    "AP": "9C:E3:30",
    "Printers": "9C:7B:EF",
    "Cameras": "00:40:8C",
    "Badge_Readers": "00:30:8E",
    "TVs": "64:1B:2F",
    "Linux": "00:C0:4F",
    "UPS": "00:C0:B7",
    "Powerstrips": "00:0D:5D",
    "RFID_Readers": "00:16:25",
}


def empty_row() -> dict[str, str]:
    return {name: "" for name in HEADER}


def convert_enterprise_row(src: dict[str, str]) -> dict[str, str]:
    group = src["endpoint_identity_group"]
    if group not in POLICY_BY_GROUP:
        raise SystemExit(f"unknown identity group {group!r}")
    # Enterprise CSV is ISE uppercase; .upper() still matches if a row is not.
    mac = src["mac"].strip().upper()
    row = empty_row()
    row["MACAddress"] = mac
    row["EndPointPolicy"] = POLICY_BY_GROUP[group]
    row["IdentityGroup"] = group
    row["Description"] = DESCRIPTION
    row["DeviceRegistrationStatus"] = "NotRegistered"
    row["BYODRegistration"] = "Unknown"
    row["StaticAssignment"] = "false"
    row["StaticGroupAssignment"] = "true"
    return row


def load_enterprise() -> list[dict[str, str]]:
    if not ENTERPRISE_CSV.is_file():
        raise SystemExit("endpoints_enterprise.csv missing; convert from that file only")
    with ENTERPRISE_CSV.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != TARGET_COUNT:
        raise SystemExit(
            f"endpoints_enterprise.csv must have {TARGET_COUNT} rows, got {len(rows)}"
        )
    return rows


def convert(enterprise: list[dict[str, str]]) -> list[dict[str, str]]:
    return [convert_enterprise_row(src) for src in enterprise]


def load_ise_import() -> tuple[list[str], list[dict[str, str]]]:
    if not ISE_IMPORT_CSV.is_file():
        raise SystemExit("endpoints_ise_import.csv missing")
    with ISE_IMPORT_CSV.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        rows = list(reader)
    return header, rows


def verify(rows: list[dict[str, str]], header: list[str] | None = None) -> None:
    errors: list[str] = []
    if header is not None and list(header) != HEADER:
        errors.append(f"header mismatch: {header}")
    if len(rows) != TARGET_COUNT:
        errors.append(f"expected {TARGET_COUNT} rows, got {len(rows)}")
    counts = Counter(r["IdentityGroup"] for r in rows)
    for group, want in GROUP_COUNTS.items():
        got = counts.get(group, 0)
        if got != want:
            errors.append(f"{group} count {got} != {want}")
    extra = set(counts) - set(GROUP_COUNTS)
    if extra:
        errors.append(f"unknown groups {sorted(extra)}")
    macs = [r["MACAddress"] for r in rows]
    if len(set(macs)) != len(macs):
        errors.append("MACAddress must be unique across 150000")
    for r in rows:
        mac = r["MACAddress"]
        group = r["IdentityGroup"]
        oui = LOCKED_OUI.get(group)
        if oui and not mac.startswith(f"{oui}:"):
            errors.append(f"{group} MAC {mac} does not start with locked OUI {oui}")
            break
        if mac != mac.upper():
            errors.append(f"MAC must be uppercase colon hex: {mac}")
            break
        if r["EndPointPolicy"] != POLICY_BY_GROUP.get(group):
            errors.append(
                f"{group} EndPointPolicy {r['EndPointPolicy']!r} "
                f"!= {POLICY_BY_GROUP.get(group)!r}"
            )
            break
        if r["Description"] != DESCRIPTION:
            errors.append(f"Description must be {DESCRIPTION!r}: {mac}")
            break
        if r["DeviceRegistrationStatus"] != "NotRegistered":
            errors.append(f"DeviceRegistrationStatus must be NotRegistered: {mac}")
            break
        if r["BYODRegistration"] != "Unknown":
            errors.append(f"BYODRegistration must be Unknown: {mac}")
            break
        if r["StaticAssignment"] != "false":
            errors.append(f"StaticAssignment must be false: {mac}")
            break
        if r["StaticGroupAssignment"] != "true":
            errors.append(f"StaticGroupAssignment must be true: {mac}")
            break
    if errors:
        raise SystemExit("verification failed:\n  " + "\n  ".join(errors))


def assert_locked_sources() -> None:
    if ISE_IMPORT_CSV.resolve() in {ENTERPRISE_CSV.resolve(), LAB_ENDPOINTS_CSV.resolve()}:
        raise SystemExit("refusing to overwrite endpoints_enterprise.csv or endpoints.csv")
    if not LAB_ENDPOINTS_CSV.is_file():
        raise SystemExit("endpoints.csv missing; lab 110 must stay")
    with LAB_ENDPOINTS_CSV.open(encoding="utf-8-sig", newline="") as f:
        lab = list(csv.DictReader(f))
    if len(lab) != 110:
        raise SystemExit(f"endpoints.csv must stay 110 lab MACs, got {len(lab)}")


def write_csv(rows: list[dict[str, str]]) -> None:
    assert_locked_sources()
    with ISE_IMPORT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows: list[dict[str, str]], wrote: bool) -> None:
    action = "wrote" if wrote else "verified"
    size = ISE_IMPORT_CSV.stat().st_size if ISE_IMPORT_CSV.is_file() else 0
    first = rows[0]
    print(f"{action} {ISE_IMPORT_CSV} ({len(rows)} rows, {size} bytes)")
    print(
        "ISE GUI/CSV import only. Terraform still csvdecodes "
        "endpoints_enterprise.csv. Do not apply both with lab endpoints.csv (110)."
    )
    print(
        f"sample {first['MACAddress']} {first['EndPointPolicy']} "
        f"{first['IdentityGroup']} {first['Description']}"
    )
    counts = Counter(r["IdentityGroup"] for r in rows)
    for group, want in GROUP_COUNTS.items():
        print(
            f"  {group} {counts[group]} policy={POLICY_BY_GROUP[group]} "
            f"oui={LOCKED_OUI[group]} lock={want}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Check committed endpoints_ise_import.csv; do not write",
    )
    args = parser.parse_args()
    assert_locked_sources()
    expected = convert(load_enterprise())
    if args.verify:
        header, rows = load_ise_import()
        verify(rows, header)
        if rows != expected:
            raise SystemExit(
                "endpoints_ise_import.csv does not match conversion of "
                "endpoints_enterprise.csv"
            )
        print_summary(rows, wrote=False)
        return 0
    verify(expected)
    write_csv(expected)
    lines = ISE_IMPORT_CSV.read_text(encoding="utf-8").splitlines()
    if len(lines) != TARGET_COUNT + 1:
        raise SystemExit(f"wc -l expected {TARGET_COUNT + 1}, got {len(lines)}")
    header, rows = load_ise_import()
    verify(rows, header)
    if rows != expected:
        raise SystemExit("wrote file does not match in-memory conversion")
    print_summary(rows, wrote=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
