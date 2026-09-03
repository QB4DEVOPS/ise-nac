#!/usr/bin/env python3
"""Build endpoints_enterprise.csv: 150,000 MACs for Terraform apply.

NDO-225 lock (CoS 2026-09-03):
  150,000 endpoint rows (Small PAN ceiling). Not 300k.
  71,000 desks. Each desk is a phone AND a PC on the SAME switch port.
  Remaining 8,000 rows are the other 9 endpoint identity groups.
  No Wi-Fi clients. AP rows are Meraki access points (infrastructure).
  Terraform apply csvdecodes this file. endpoint_count default 150000.
  Lab endpoints.csv / endpoints.yaml / generate_endpoints.py stay 110 in Git
  as inventory only. Do not apply both (150k+110 will not fit a Small PAN).

Locked per-group counts:
  Phones 71000, Windows 71000, AP 2250, Printers 1550, Cameras 1500,
  Badge_Readers 800, TVs 600, Linux 500, UPS 400, Powerstrips 250,
  RFID_Readers 150. Total 150000.

Placement (devices.csv math is exact, not ugly):
  71,000 desks / 5 = 14,200 switches with Gi1/0/1 .. Gi1/0/5.
  First 14,200 of 15,000 devices.csv switches get those 5 desks.
  Last 800 switches have no desks (not every switch needs 5).
  Phone + PC share that port (classic voice+data on one access port).
  Non-desk: own port Gi1/0/6 (ABOVE the desk range) on the last 8,000
  switches, one device each. Empty `desk` column. Site is the switch site.
  Exact split: AP+Printers+Cameras+Badge_Readers+TVs+Linux = 7,200 land on
  switches that also have desks; UPS+Powerstrips+RFID_Readers = 800 land on
  the 800 desk-less switches.

Pattern: {IEEE MA-L OUI}:{generated last 3 octets}
OUI source of truth (MA-L): https://standards-oui.ieee.org/oui/oui.txt
Reuse lab vendor OUIs from generate_endpoints.py. Last 3 octets are hashed
suffixes — unique across 150k, not 00:00:01–0A, not 02:00:GG, not copied
from a NIC. Not a 150k YAML (GitHub size).

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

# Locked CoS mapping. Same IEEE MA-L OUIs as scripts/generate_endpoints.py.
# Do not invent, randomize, or swap. Stop if IEEE MA-L disagrees.
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
ORG_ALIASES = {
    "apc": ("american power conversion",),
}

# NDO-225 locked counts. Desks first, then non-desk in this order.
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
DESK_GROUPS = ("Phones", "Windows")
NON_DESK_GROUPS = (
    "AP",
    "Printers",
    "Cameras",
    "Badge_Readers",
    "TVs",
    "Linux",
    "UPS",
    "Powerstrips",
    "RFID_Readers",
)

TARGET_SWITCHES = 15000
DESKS_PER_SWITCH = 5
DESK_COUNT = GROUP_COUNTS["Phones"]  # 71,000
DESK_SWITCH_COUNT = DESK_COUNT // DESKS_PER_SWITCH  # 14,200
ROWS_PER_DESK = 2  # phone + PC
NON_DESK_TOTAL = sum(GROUP_COUNTS[g] for g in NON_DESK_GROUPS)  # 8,000
NON_DESK_SWITCH_COUNT = NON_DESK_TOTAL  # one non-desk device per switch
TARGET_COUNT = DESK_COUNT * ROWS_PER_DESK + NON_DESK_TOTAL  # 150,000
PORT_PREFIX = "Gi1/0/"
DESK_PORT_MAX = DESKS_PER_SWITCH  # Gi1/0/1 .. Gi1/0/5
NON_DESK_PORT_START = DESK_PORT_MAX + 1  # Gi1/0/6 and above
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
DESK_ID_RE = re.compile(r"^desk-\d{6}$")
# Documented inventory salt (not a secret). Different from the 110 lab salt.
ENTERPRISE_SALT = "ise-nac-enterprise-ieee-mal-v1"
TRIVIAL_LAST = {f"00:00:{n:02x}" for n in range(1, 11)}
DESCRIPTION = "Generated. Not hardware. IEEE MA-L."
BANNED = ("password", "token", "secret")
WIFI_NEEDLES = ("wi-fi", "wifi", "wireless client")


def _assert_lock_math() -> None:
    if DESK_COUNT % DESKS_PER_SWITCH != 0:
        raise SystemExit(f"DESK_COUNT {DESK_COUNT} is not divisible by {DESKS_PER_SWITCH}")
    if GROUP_COUNTS["Phones"] != GROUP_COUNTS["Windows"]:
        raise SystemExit("Phones and Windows counts must match (one pair per desk)")
    if sum(GROUP_COUNTS.values()) != TARGET_COUNT:
        raise SystemExit(
            f"GROUP_COUNTS sum {sum(GROUP_COUNTS.values())} != TARGET_COUNT {TARGET_COUNT}"
        )
    if TARGET_COUNT != 150000:
        raise SystemExit("lock is 150000 rows")
    if DESK_COUNT != 71000:
        raise SystemExit("lock is 71000 desks")
    if NON_DESK_TOTAL != 8000:
        raise SystemExit("lock is 8000 non-desk rows")
    if DESK_SWITCH_COUNT + (TARGET_SWITCHES - DESK_SWITCH_COUNT) != TARGET_SWITCHES:
        raise SystemExit("desk switch split must cover devices.csv")
    if TARGET_SWITCHES - NON_DESK_SWITCH_COUNT + NON_DESK_SWITCH_COUNT != TARGET_SWITCHES:
        raise SystemExit("non-desk switch split must cover devices.csv")
    extra = set(GROUP_COUNTS) - set(LOCKED_OUI)
    missing = set(LOCKED_OUI) - set(GROUP_COUNTS)
    if extra or missing:
        raise SystemExit(f"group lock mismatch extra={sorted(extra)} missing={sorted(missing)}")
    if "Wi-Fi Clients" in GROUP_COUNTS or "WiFi" in GROUP_COUNTS:
        raise SystemExit("do not invent a Wi-Fi Clients group")


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
        if ports < NON_DESK_PORT_START:
            raise SystemExit(
                f"{r['hostname']} port_count {ports} < Gi1/0/{NON_DESK_PORT_START}"
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


def port_slot(port: str) -> int | None:
    if not re.fullmatch(rf"{re.escape(PORT_PREFIX)}[1-9]\d*", port):
        return None
    return int(port.rsplit("/", 1)[-1])


def endpoint_row(
    *,
    group: str,
    suffix: str,
    ieee_org: str,
    desk: str,
    switch: str,
    port: str,
    site: str,
) -> dict[str, str]:
    oui, _locked = LOCKED_OUI[group]
    return {
        "mac": f"{oui}:{suffix}",
        "endpoint_identity_group": group,
        "oui": oui,
        "organization": ieee_org,
        "description": DESCRIPTION,
        "desk": desk,
        "switch": switch,
        "port": port,
        "site": site,
    }


def build(devices: list[dict[str, str]], ieee_org_by_group: dict[str, str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    used_suffixes = lab_suffixes()
    desk_n = 0
    for sw in devices[:DESK_SWITCH_COUNT]:
        hostname = sw["hostname"]
        site = sw["site_code"]
        for slot in range(1, DESKS_PER_SWITCH + 1):
            desk_n += 1
            did = desk_id(desk_n)
            port = port_name(slot)
            for group in DESK_GROUPS:
                suffix = nic_suffix(f"{group}|{did}", used_suffixes)
                rows.append(
                    endpoint_row(
                        group=group,
                        suffix=suffix,
                        ieee_org=ieee_org_by_group[group],
                        desk=did,
                        switch=hostname,
                        port=port,
                        site=site,
                    )
                )
    if desk_n != DESK_COUNT:
        raise SystemExit(f"internal desk count {desk_n} != {DESK_COUNT}")

    # Last 8,000 switches; one non-desk device each on Gi1/0/6.
    non_desk_switches = devices[-NON_DESK_SWITCH_COUNT:]
    nd_i = 0
    for group in NON_DESK_GROUPS:
        want = GROUP_COUNTS[group]
        for seq in range(1, want + 1):
            sw = non_desk_switches[nd_i]
            port = port_name(NON_DESK_PORT_START)
            suffix = nic_suffix(f"{group}|infra|{seq:06d}", used_suffixes)
            rows.append(
                endpoint_row(
                    group=group,
                    suffix=suffix,
                    ieee_org=ieee_org_by_group[group],
                    desk="",  # non-desk: empty desk column
                    switch=sw["hostname"],
                    port=port,
                    site=sw["site_code"],
                )
            )
            nd_i += 1
    if nd_i != NON_DESK_TOTAL:
        raise SystemExit(f"internal non-desk count {nd_i} != {NON_DESK_TOTAL}")
    if len(rows) != TARGET_COUNT:
        raise SystemExit(f"internal row count {len(rows)} != {TARGET_COUNT}")
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
    for group, want in GROUP_COUNTS.items():
        got = per_group.get(group)
        if got != want:
            errors.append(f"{group} {got} != {want}")
    extra = set(per_group) - set(GROUP_COUNTS)
    if extra:
        errors.append(f"unknown groups in enterprise list: {sorted(extra)}")
    if any("wifi" in g.lower() or "wi-fi" in g.lower() for g in per_group):
        errors.append("Wi-Fi client group is not in this inventory")

    desk_rows = [r for r in rows if (r.get("desk") or "").strip()]
    non_desk_rows = [r for r in rows if not (r.get("desk") or "").strip()]
    if len(non_desk_rows) != NON_DESK_TOTAL:
        errors.append(f"non-desk rows {len(non_desk_rows)} != {NON_DESK_TOTAL}")
    if len(desk_rows) != DESK_COUNT * ROWS_PER_DESK:
        errors.append(f"desk rows {len(desk_rows)} != {DESK_COUNT * ROWS_PER_DESK}")

    by_desk: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in desk_rows:
        did = r["desk"]
        if not DESK_ID_RE.fullmatch(did):
            errors.append(f"desk id {did!r} is not desk-NNNNNN")
            break
        by_desk[did].append(r)
    if len(by_desk) != DESK_COUNT:
        errors.append(f"desk count {len(by_desk)} != {DESK_COUNT}")

    device_by_host = {d["hostname"]: d for d in devices}
    desks_per_switch: Counter[str] = Counter()
    for desk, items in by_desk.items():
        if len(items) != ROWS_PER_DESK:
            errors.append(f"{desk} has {len(items)} rows, want {ROWS_PER_DESK}")
            break
        groups = {i["endpoint_identity_group"] for i in items}
        if groups != set(DESK_GROUPS):
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
        slot = port_slot(port)
        if slot is None:
            errors.append(f"{desk} port {port!r} is not {PORT_PREFIX}N")
            break
        if not (1 <= slot <= DESK_PORT_MAX):
            errors.append(f"{desk} port {port} outside Gi1/0/1..{DESK_PORT_MAX}")
            break
        desks_per_switch[switch] += 1

    if any(v != DESKS_PER_SWITCH for v in desks_per_switch.values()):
        bad = {k: v for k, v in desks_per_switch.items() if v != DESKS_PER_SWITCH}
        errors.append(f"desks per switch must be {DESKS_PER_SWITCH}: {list(bad.items())[:5]}")
    if len(desks_per_switch) != DESK_SWITCH_COUNT:
        errors.append(
            f"switches with desks {len(desks_per_switch)} != {DESK_SWITCH_COUNT} "
            f"(not every switch needs {DESKS_PER_SWITCH} desks)"
        )
    expected_desk_hosts = {d["hostname"] for d in devices[:DESK_SWITCH_COUNT]}
    if set(desks_per_switch) != expected_desk_hosts:
        errors.append("desk switches must be the first 14200 devices.csv rows")

    non_desk_hosts: set[str] = set()
    for r in non_desk_rows:
        group = r["endpoint_identity_group"]
        if group in DESK_GROUPS:
            errors.append(f"desk group {group} on a non-desk row {r.get('mac')}")
            break
        switch, port, site = r["switch"], r["port"], r["site"]
        sw = device_by_host.get(switch)
        if sw is None:
            errors.append(f"non-desk switch {switch!r} not in devices.csv")
            break
        if sw["site_code"] != site:
            errors.append(f"non-desk site {site!r} != devices.csv {sw['site_code']!r}")
            break
        slot = port_slot(port)
        if slot is None:
            errors.append(f"non-desk port {port!r} is not {PORT_PREFIX}N")
            break
        if slot < NON_DESK_PORT_START:
            errors.append(f"non-desk port {port} is not above desk range Gi1/0/{DESK_PORT_MAX}")
            break
        if slot > int(sw["port_count"]):
            errors.append(f"non-desk port {port} exceeds {switch} port_count {sw['port_count']}")
            break
        non_desk_hosts.add(switch)

    if len(non_desk_hosts) != NON_DESK_SWITCH_COUNT:
        errors.append(
            f"switches with non-desk {len(non_desk_hosts)} != {NON_DESK_SWITCH_COUNT} "
            "(one non-desk device per chosen switch)"
        )
    expected_nd_hosts = {d["hostname"] for d in devices[-NON_DESK_SWITCH_COUNT:]}
    if non_desk_hosts and non_desk_hosts != expected_nd_hosts:
        errors.append("non-desk switches must be the last 8000 devices.csv rows")

    place_groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for r in rows:
        place_groups[(r["switch"], r["port"])].append(r["endpoint_identity_group"])
    for place, groups in place_groups.items():
        if sorted(groups) == ["Phones", "Windows"]:
            continue
        if len(groups) == 1 and groups[0] in NON_DESK_GROUPS:
            continue
        errors.append(f"port occupancy {place} groups {groups} is not desk pair or single non-desk")
        break

    for r in rows:
        mac = r["mac"]
        group = r["endpoint_identity_group"]
        if group not in LOCKED_OUI:
            errors.append(f"unknown group {group}")
            break
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
        if any(needle in packed for needle in WIFI_NEEDLES):
            errors.append("Wi-Fi clients are not in this inventory")
            break
        if any(bad in packed for bad in BANNED):
            errors.append(f"banned string present on {r.get('mac')}")
            break

    if TARGET_COUNT != 150000:
        errors.append("lock is 150000 rows")
    if DESK_COUNT != 71000:
        errors.append("lock is 71000 desks")
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
    pc = next(
        r
        for r in rows
        if r["desk"] == phone["desk"] and r["endpoint_identity_group"] == "Windows"
    )
    last_desk_id = desk_id(DESK_COUNT)
    last_phone = next(
        r for r in rows if r["desk"] == last_desk_id and r["endpoint_identity_group"] == "Phones"
    )
    last_pc = next(
        r for r in rows if r["desk"] == last_desk_id and r["endpoint_identity_group"] == "Windows"
    )
    first_ap = next(r for r in rows if r["endpoint_identity_group"] == "AP")
    last_rfid = next(r for r in reversed(rows) if r["endpoint_identity_group"] == "RFID_Readers")
    action = "wrote" if wrote else "verified"
    size = ENTERPRISE_CSV.stat().st_size if ENTERPRISE_CSV.is_file() else 0
    print(f"{action} {ENTERPRISE_CSV} ({len(rows)} rows, {size} bytes)")
    print(
        f"lock desks={DESK_COUNT} desk_switches={DESK_SWITCH_COUNT} "
        f"non_desk={NON_DESK_TOTAL} rows={TARGET_COUNT} "
        f"switches={TARGET_SWITCHES} desks_per_switch={DESKS_PER_SWITCH}"
    )
    print(
        "terraform apply csvdecodes this file; "
        f"endpoint_count default={TARGET_COUNT}. Lab endpoints.csv is inventory only."
    )
    print(
        f"sample {phone['desk']} {phone['switch']} {phone['port']} {phone['site']} "
        f"Phones {phone['mac']} | Windows {pc['mac']}"
    )
    print(
        f"last   {last_phone['desk']} {last_phone['switch']} {last_phone['port']} "
        f"{last_phone['site']} Phones {last_phone['mac']} | Windows {last_pc['mac']}"
    )
    print(
        f"non-desk desk={first_ap['desk']!r} {first_ap['switch']} {first_ap['port']} "
        f"{first_ap['site']} AP {first_ap['mac']}"
    )
    print(
        f"last-nd desk={last_rfid['desk']!r} {last_rfid['switch']} {last_rfid['port']} "
        f"{last_rfid['site']} RFID_Readers {last_rfid['mac']}"
    )
    counts = Counter(r["endpoint_identity_group"] for r in rows)
    for group, want in GROUP_COUNTS.items():
        oui, locked_org = LOCKED_OUI[group]
        print(f"  {group} {counts[group]} {oui} locked={locked_org!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Check committed endpoints_enterprise.csv; do not write or fetch IEEE",
    )
    args = parser.parse_args()
    _assert_lock_math()
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
        print(f"  ieee {group} {oui} locked={locked_org!r} ieee={ieee_org_by_group[group]!r}")
    print(f"ieee_mal={IEEE_OUI_URL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
