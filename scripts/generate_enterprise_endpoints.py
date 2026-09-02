#!/usr/bin/env python3
"""Build endpoints_enterprise.csv: 150,000 Git-only desk MACs.

NDO-200 lock (Robert 2026-09-01, CoS restated):
  150,000 endpoint rows. Not 300k.
  75,000 desks. Each desk is a phone AND a PC on the SAME switch port.
  Phones OUI 00:04:f2 (Polycom). Windows/PC OUI 10:e7:c6 (Hewlett Packard).
  110 lab MACs in endpoints.csv stay the pan1 default. This file is Git
  inventory only. Terraform must not read it. Do not apply until Robert says so.

Placement (devices.csv math is exact, not ugly):
  15,000 access switches × 5 desks = 75,000 desks.
  Each switch uses Gi1/0/1 .. Gi1/0/5 (port_count is 48). Phone + PC share
  that port (classic voice+data on one access port).

Pattern: {IEEE MA-L OUI}:{generated last 3 octets}
OUI source of truth (MA-L): https://standards-oui.ieee.org/oui/oui.txt
Last 3 octets are hashed suffixes — unique across 150k, not 00:00:01–0A,
not 02:00:GG, not copied from a NIC. Not a 150k YAML (GitHub size).

Rebuild:
  python3 scripts/generate_enterprise_endpoints.py
Verify only (no write, no IEEE download):
  python3 scripts/generate_enterprise_endpoints.py --verify
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEVICES_CSV = ROOT / "devices.csv"
LAB_ENDPOINTS_CSV = ROOT / "endpoints.csv"
ENTERPRISE_CSV = ROOT / "endpoints_enterprise.csv"
LAB_ENDPOINTS_YAML = ROOT / "endpoints.yaml"

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
IEEE_HEX_RE = re.compile(
    r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$"
)

# Locked desk groups only. Do not invent AP/Printers/etc. at this scale.
LOCKED_OUI = {
    "Phones": ("00:04:f2", "Polycom"),
    "Windows": ("10:e7:c6", "Hewlett Packard"),
}
ORG_ALIASES = {
    "apc": ("american power conversion",),
}

TARGET_SWITCHES = 15000
DESKS_PER_SWITCH = 5
DESK_COUNT = TARGET_SWITCHES * DESKS_PER_SWITCH  # 75,000
ROWS_PER_DESK = 2  # phone + PC
TARGET_COUNT = DESK_COUNT * ROWS_PER_DESK  # 150,000
PORT_PREFIX = "Gi1/0/"
COLUMNS = [
    "mac",
    "endpoint_identity_group",
    "oui",
    "organization",
    "description",
    "desk",
    "switch",
    "port",
    "site",
]
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
# Documented inventory salt (not a secret). Different from the 110 lab salt.
ENTERPRISE_SALT = "ise-nac-enterprise-ieee-mal-v1"
TRIVIAL_LAST = {f"00:00:{n:02x}" for n in range(1, 11)}
DESCRIPTION = "Generated. Not hardware. IEEE MA-L."
BANNED = ("password", "token", "secret")


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
                headers={"User-Agent": "ise-nac-enterprise-oui-verify/1.0"},
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


def nic_suffix(key: str, used: set[str]) -> str:
    """Deterministic 24-bit suffix from SHA-256. Not copied from hardware."""
    n = 0
    while n < 4096:
        digest = hashlib.sha256(f"{ENTERPRISE_SALT}|{key}|{n}".encode("utf-8")).digest()
        suffix = ":".join(f"{b:02x}" for b in digest[:3])
        if suffix not in used and not is_trivial_nic_suffix(suffix):
            used.add(suffix)
            return suffix
        n += 1
    raise SystemExit(f"could not allocate a non-trivial NIC suffix for {key}")


def load_devices() -> list[dict[str, str]]:
    if not DEVICES_CSV.is_file():
        raise SystemExit(f"missing {DEVICES_CSV}")
    with DEVICES_CSV.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != TARGET_SWITCHES:
        raise SystemExit(f"devices.csv expected {TARGET_SWITCHES} switches, got {len(rows)}")
    hostnames = [r["hostname"] for r in rows]
    if len(hostnames) != len(set(hostnames)):
        raise SystemExit("devices.csv has duplicate hostnames")
    for r in rows:
        try:
            ports = int(r["port_count"])
        except (KeyError, ValueError) as exc:
            raise SystemExit(f"devices.csv row missing port_count: {exc}") from exc
        if ports < DESKS_PER_SWITCH:
            raise SystemExit(
                f"{r['hostname']} port_count {ports} < {DESKS_PER_SWITCH} desks"
            )
    return rows


def lab_suffixes() -> set[str]:
    """Reserve the 110 lab NIC suffixes so enterprise MACs cannot collide."""
    used: set[str] = set()
    if not LAB_ENDPOINTS_CSV.is_file():
        return used
    with LAB_ENDPOINTS_CSV.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            mac = (row.get("mac") or "").strip()
            if mac:
                used.add(":".join(mac.split(":")[3:]))
    return used


def desk_id(n: int) -> str:
    return f"desk-{n:06d}"


def port_name(slot: int) -> str:
    return f"{PORT_PREFIX}{slot}"


def build(devices: list[dict[str, str]], ieee_org_by_group: dict[str, str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    used_suffixes = lab_suffixes()
    desk_n = 0
    for sw in devices:
        hostname = sw["hostname"]
        site = sw["site_code"]
        for slot in range(1, DESKS_PER_SWITCH + 1):
            desk_n += 1
            did = desk_id(desk_n)
            port = port_name(slot)
            for group in ("Phones", "Windows"):
                oui, _locked = LOCKED_OUI[group]
                suffix = nic_suffix(f"{group}|{did}", used_suffixes)
                mac = f"{oui}:{suffix}"
                rows.append(
                    {
                        "mac": mac,
                        "endpoint_identity_group": group,
                        "oui": oui,
                        "organization": ieee_org_by_group[group],
                        "description": DESCRIPTION,
                        "desk": did,
                        "switch": hostname,
                        "port": port,
                        "site": site,
                    }
                )
    if desk_n != DESK_COUNT:
        raise SystemExit(f"internal desk count {desk_n} != {DESK_COUNT}")
    return rows


def load_enterprise_csv() -> list[dict[str, str]]:
    if not ENTERPRISE_CSV.is_file():
        raise SystemExit(f"missing {ENTERPRISE_CSV}")
    with ENTERPRISE_CSV.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != COLUMNS:
            raise SystemExit(
                f"{ENTERPRISE_CSV.name} columns {reader.fieldnames} != {COLUMNS}"
            )
        return list(reader)


def verify(rows: list[dict[str, str]], devices: list[dict[str, str]]) -> None:
    errors: list[str] = []
    if len(rows) != TARGET_COUNT:
        errors.append(f"row count {len(rows)} != {TARGET_COUNT} (not 300k; not 110)")
    macs = [r["mac"] for r in rows]
    if len(macs) != len(set(macs)):
        dup = [m for m, c in Counter(macs).items() if c > 1]
        errors.append(f"duplicate MACs: {dup[:5]}")
    suffixes = [":".join(m.split(":")[3:]) for m in macs]
    if len(suffixes) != len(set(suffixes)):
        errors.append("last-3-octet suffixes must be unique across 150000")
    reserved = lab_suffixes()
    overlap = reserved.intersection(suffixes)
    if overlap:
        errors.append(f"enterprise suffix collides with lab 110: {sorted(overlap)[:5]}")
    per_group = Counter(r["endpoint_identity_group"] for r in rows)
    if per_group.get("Phones") != DESK_COUNT:
        errors.append(f"Phones {per_group.get('Phones')} != {DESK_COUNT}")
    if per_group.get("Windows") != DESK_COUNT:
        errors.append(f"Windows {per_group.get('Windows')} != {DESK_COUNT}")
    extra = set(per_group) - {"Phones", "Windows"}
    if extra:
        errors.append(f"unknown groups in enterprise list: {sorted(extra)}")

    by_desk: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in rows:
        by_desk[r["desk"]].append(r)
    if len(by_desk) != DESK_COUNT:
        errors.append(f"desk count {len(by_desk)} != {DESK_COUNT}")

    device_by_host = {d["hostname"]: d for d in devices}
    desks_per_switch: Counter[str] = Counter()
    for desk, items in by_desk.items():
        if len(items) != ROWS_PER_DESK:
            errors.append(f"{desk} has {len(items)} rows, want {ROWS_PER_DESK}")
            break
        groups = {i["endpoint_identity_group"] for i in items}
        if groups != {"Phones", "Windows"}:
            errors.append(f"{desk} groups {groups} != Phones+Windows")
            break
        places = {(i["switch"], i["port"], i["site"]) for i in items}
        if len(places) != 1:
            errors.append(f"{desk} phone/PC not on same switch+port+site: {places}")
            break
        switch, port, site = items[0]["switch"], items[0]["port"], items[0]["site"]
        sw = device_by_host.get(switch)
        if sw is None:
            errors.append(f"{desk} switch {switch!r} not in devices.csv")
            break
        if sw["site_code"] != site:
            errors.append(f"{desk} site {site!r} != devices.csv {sw['site_code']!r}")
            break
        if not re.fullmatch(rf"{re.escape(PORT_PREFIX)}[1-9]\d*", port):
            errors.append(f"{desk} port {port!r} is not {PORT_PREFIX}N")
            break
        slot = int(port.rsplit("/", 1)[-1])
        if not (1 <= slot <= DESKS_PER_SWITCH):
            errors.append(f"{desk} port {port} outside Gi1/0/1..{DESKS_PER_SWITCH}")
            break
        desks_per_switch[switch] += 1

    if any(v != DESKS_PER_SWITCH for v in desks_per_switch.values()):
        bad = {k: v for k, v in desks_per_switch.items() if v != DESKS_PER_SWITCH}
        errors.append(f"desks per switch must be {DESKS_PER_SWITCH}: {list(bad.items())[:5]}")
    if len(desks_per_switch) != TARGET_SWITCHES:
        errors.append(
            f"switches used {len(desks_per_switch)} != {TARGET_SWITCHES} devices.csv rows"
        )

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
        if not (r.get("organization") or "").strip():
            errors.append(f"{group} must cite IEEE organization")
            break
        suffix = ":".join(mac.split(":")[3:])
        if is_trivial_nic_suffix(suffix):
            errors.append(f"trivial NIC suffix: {mac}")
            break
        desc = r["description"].casefold()
        if "not hardware" not in desc:
            errors.append(f"description must say not hardware: {mac}")
            break
        if mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            errors.append(f"banned MAC: {mac}")
            break
        if "guest" in group.lower():
            errors.append("guest appears in group list")
            break

    for r in rows:
        packed = ",".join(r.get(c) or "" for c in COLUMNS).lower()
        if "guest" in packed:
            errors.append("guest appears in enterprise inventory")
            break
        if any(bad in packed for bad in BANNED):
            errors.append(f"banned string present on {r.get('mac')}")
            break

    if TARGET_COUNT != 150000:
        errors.append("lock is 150000 rows")
    if DESK_COUNT != 75000:
        errors.append("lock is 75000 desks")
    if errors:
        raise SystemExit("verification failed:\n  " + "\n  ".join(errors))


def assert_lab_untouched() -> None:
    """Hard lock: do not replace or grow the 110 lab set."""
    if not LAB_ENDPOINTS_CSV.is_file():
        raise SystemExit("endpoints.csv missing; lab 110 must stay")
    with LAB_ENDPOINTS_CSV.open(encoding="utf-8-sig", newline="") as f:
        lab = list(csv.DictReader(f))
    if len(lab) != 110:
        raise SystemExit(f"endpoints.csv must stay 110 lab MACs, got {len(lab)}")
    if LAB_ENDPOINTS_YAML.is_file():
        text = LAB_ENDPOINTS_YAML.read_text(encoding="utf-8")
        # Cheap size guard: a 150k YAML would be huge.
        if text.count("\n") > 2000:
            raise SystemExit("endpoints.yaml grew past the 110 lab set")


def write_csv(rows: list[dict[str, str]]) -> None:
    if ENTERPRISE_CSV.resolve() == LAB_ENDPOINTS_CSV.resolve():
        raise SystemExit("refusing to overwrite endpoints.csv")
    with ENTERPRISE_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def print_summary(rows: list[dict[str, str]], wrote: bool) -> None:
    phone = next(r for r in rows if r["endpoint_identity_group"] == "Phones")
    pc = next(r for r in rows if r["desk"] == phone["desk"] and r["endpoint_identity_group"] == "Windows")
    last_desk = rows[-1]["desk"]
    last_phone = next(r for r in rows if r["desk"] == last_desk and r["endpoint_identity_group"] == "Phones")
    last_pc = next(r for r in rows if r["desk"] == last_desk and r["endpoint_identity_group"] == "Windows")
    action = "wrote" if wrote else "verified"
    size = ENTERPRISE_CSV.stat().st_size if ENTERPRISE_CSV.is_file() else 0
    print(f"{action} {ENTERPRISE_CSV} ({len(rows)} rows, {size} bytes)")
    print(
        f"lock desks={DESK_COUNT} rows={TARGET_COUNT} "
        f"switches={TARGET_SWITCHES} desks_per_switch={DESKS_PER_SWITCH}"
    )
    print(f"pan1 apply stays endpoints.csv / endpoint_count=110. Do not apply this file.")
    print(
        f"sample {phone['desk']} {phone['switch']} {phone['port']} {phone['site']} "
        f"Phones {phone['mac']} | Windows {pc['mac']}"
    )
    print(
        f"last   {last_phone['desk']} {last_phone['switch']} {last_phone['port']} "
        f"{last_phone['site']} Phones {last_phone['mac']} | Windows {last_pc['mac']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Check committed endpoints_enterprise.csv; do not write or fetch IEEE",
    )
    args = parser.parse_args()
    assert_lab_untouched()
    devices = load_devices()
    if args.verify:
        rows = load_enterprise_csv()
        verify(rows, devices)
        print_summary(rows, wrote=False)
        return 0
    ieee = parse_ieee_mal(fetch_ieee_oui_text())
    ieee_org_by_group = verify_locked_ouis(ieee)
    rows = build(devices, ieee_org_by_group)
    verify(rows, devices)
    write_csv(rows)
    lines = ENTERPRISE_CSV.read_text(encoding="utf-8-sig").splitlines()
    if len(lines) != TARGET_COUNT + 1:
        raise SystemExit(f"wc -l expected {TARGET_COUNT + 1}, got {len(lines)}")
    print_summary(rows, wrote=True)
    for group, (oui, locked_org) in LOCKED_OUI.items():
        print(f"  {group} {oui} locked={locked_org!r} ieee={ieee_org_by_group[group]!r}")
    print(f"ieee_mal={IEEE_OUI_URL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
