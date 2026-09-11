#!/usr/bin/env python3
"""Stellar Express Courier showcase inventories (demo only).

Default: write *_sample.csv companions for fake_ise_system_full.yaml.
--full: write production-ish stellar_express_*.csv locally (gitignored).

NOT Terraform-wired. Never writes production apply filenames
(sites.csv, devices.csv, endpoints.csv, endpoints_enterprise.csv).

Rebuild samples:
  python3 fake_stellar/scripts/generate_stellar_inventory.py
Verify:
  python3 fake_stellar/scripts/generate_stellar_inventory.py --verify
Local full scale (not committed until CoS locks counts):
  python3 fake_stellar/scripts/generate_stellar_inventory.py --full
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

SCRIPT = Path(__file__).resolve()
PACK = SCRIPT.parents[1]
REPO = SCRIPT.parents[2]

# Demo-only names. Never collide with production apply files.
PRODUCTION_FILENAMES = {
    "sites.csv",
    "devices.csv",
    "endpoints.csv",
    "endpoints_enterprise.csv",
    "endpoints_ise_import.csv",
    "nac.yaml",
    "users.csv",
    "ndgs.csv",
}

SITES_SAMPLE = PACK / "stellar_express_sites_sample.csv"
DEVICES_SAMPLE = PACK / "stellar_express_devices_sample.csv"
ENDPOINTS_SAMPLE = PACK / "stellar_express_endpoints_sample.csv"
LOCATION_SAMPLE = PACK / "stellar_express_location_ndgs_sample.csv"

SITES_FULL = PACK / "stellar_express_sites.csv"
DEVICES_FULL = PACK / "stellar_express_devices.csv"
ENDPOINTS_FULL = PACK / "stellar_express_endpoints.csv"
LOCATION_FULL = PACK / "stellar_express_location_ndgs.csv"

CITY_CATALOG = REPO / "sites.csv"
FULL_YAML = REPO / "fake_ise_system_full.yaml"
LIGHT_YAML = REPO / "fake_ise_system.yaml"
LAB_ENDPOINTS = REPO / "endpoints.csv"

SCHEMA_KEYS = (
    "lab",
    "ndgs",
    "location_ndgs",
    "sites",
    "tacacs_authc",
    "tacacs_authz",
    "devices",
    "command_sets",
    "shell_profiles",
    "endpoint_identity_groups",
    "endpoints",
    "allowed_protocols",
    "authorization_profiles",
    "network_access_policy_sets",
    "network_access_authc",
    "network_access_authz",
    "users",
)

# Showcase campuses that stay in the YAML shell. Stellar types (not production).
SHOWCASE_SITES = [
    {
        "id": "us-houston",
        "city": "Houston",
        "admin1": "Texas",
        "cc": "us",
        "type": "hq",
        "facility": "world-hq-control-campus",
    },
    {
        "id": "us-dallas",
        "city": "Dallas",
        "admin1": "Texas",
        "cc": "us",
        "type": "dc",
        "facility": "sortation-fabric",
    },
    {
        "id": "us-seattle",
        "city": "Seattle",
        "admin1": "Washington",
        "cc": "us",
        "type": "regional",
        "facility": "pacific-hub",
    },
    {
        "id": "us-chicago",
        "city": "Chicago",
        "admin1": "Illinois",
        "cc": "us",
        "type": "regional",
        "facility": "midwest-hub",
    },
    {
        "id": "gb-london",
        "city": "London",
        "admin1": "England",
        "cc": "gb",
        "type": "regional",
        "facility": "europe-hub",
    },
    {
        "id": "us-portland-or",
        "city": "Portland",
        "admin1": "Oregon",
        "cc": "us",
        "type": "branch",
        "facility": "neighborhood-depot",
    },
    {
        "id": "us-milwaukee",
        "city": "Milwaukee",
        "admin1": "Wisconsin",
        "cc": "us",
        "type": "branch",
        "facility": "neighborhood-depot",
    },
    {
        "id": "de-berlin",
        "city": "Berlin",
        "admin1": "Berlin",
        "cc": "de",
        "type": "branch",
        "facility": "neighborhood-depot",
    },
    {
        "id": "jp-tokyo",
        "city": "Tokyo",
        "admin1": "Tokyo",
        "cc": "jp",
        "type": "branch",
        "facility": "neighborhood-depot",
    },
]

# Hostname token + RFC 5737 unique IPs for the committed sample (matches YAML).
SAMPLE_DEVICE_PLAN = {
    "us-houston": ("ushou", "192.0.2", 1, 4),
    "us-dallas": ("usdal", "192.0.2", 11, 4),
    "us-seattle": ("ussea", "198.51.100", 1, 3),
    "us-chicago": ("uschi", "198.51.100", 11, 3),
    "us-portland-or": ("uspdx", "198.51.100", 21, 3),
    "us-milwaukee": ("usmil", "198.51.100", 31, 3),
    "gb-london": ("gblon", "203.0.113", 1, 3),
    "de-berlin": ("deber", "203.0.113", 11, 3),
    "jp-tokyo": ("jptyo", "203.0.113", 21, 3),
}

STELLAR_TYPE_OVERRIDES = {
    "us-houston": "hq",
    "us-dallas": "dc",
    "gb-london": "regional",
    "us-portland-or": "branch",
    "us-milwaukee": "branch",
}

FACILITY = {
    "hq": "world-hq-control-campus",
    "dc": "sortation-fabric",
    "regional": "regional-hub",
    "branch": "neighborhood-depot",
}

DOC_NET = {
    "hq": "192.0.2",
    "dc": "192.0.2",
    "regional": "198.51.100",
    "branch": "203.0.113",
}

SITE_COLUMNS = ["id", "city", "admin1", "cc", "type", "facility"]
DEVICE_COLUMNS = [
    "hostname",
    "mgmt_ip",
    "site_code",
    "site_name",
    "country_code",
    "role",
    "type",
    "os",
    "port_count",
]
ENDPOINT_COLUMNS = [
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
LOCATION_COLUMNS = ["ndg", "description", "placeholder", "parent"]

# Locked IEEE MA-L OUIs (same groups as this repo). Do not invent others.
LOCKED_OUI = {
    "Phones": ("00:04:F2", "Polycom"),
    "AP": ("9C:E3:30", "Cisco Meraki"),
    "Printers": ("9C:7B:EF", "Hewlett Packard"),
    "TVs": ("64:1B:2F", "Samsung Electronics Co.,Ltd"),
    "Badge_Readers": ("00:30:8E", "Crossmatch Technologies/HID Global"),
    "Cameras": ("00:40:8C", "Axis Communications AB"),
    "UPS": ("00:C0:B7", "AMERICAN POWER CONVERSION CORP"),
    "Powerstrips": ("00:0D:5D", "Raritan Computer, Inc"),
    "Linux": ("00:C0:4F", "Dell Inc."),
    "Windows": ("10:E7:C6", "Hewlett Packard"),
    "RFID_Readers": ("00:16:25", "Impinj, Inc."),
}
LOCKED_GROUPS = tuple(LOCKED_OUI)

# Production-ish default (NDO-225 mix). Not CoS-locked for this pack.
FULL_GROUP_COUNTS = {
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
SAMPLE_MACS_PER_GROUP = 10
SAMPLE_ENDPOINT_COUNT = len(LOCKED_GROUPS) * SAMPLE_MACS_PER_GROUP
FULL_SITE_COUNT = 400
FULL_DEVICE_COUNT = 15000
FULL_ENDPOINT_COUNT = 150000
REGIONAL_SWITCHES = 48
BRANCH_SWITCHES = 36
HQ_SWITCHES = 48
DC_SWITCHES = 48
DESKS_PER_SWITCH = 5
DESK_COUNT = FULL_GROUP_COUNTS["Phones"]
DESK_SWITCH_COUNT = DESK_COUNT // DESKS_PER_SWITCH
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
NON_DESK_TOTAL = sum(FULL_GROUP_COUNTS[g] for g in NON_DESK_GROUPS)

STELLAR_SALT = "stellar-express-courier-showcase-ieee-mal-v1"
MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
TRIVIAL_LAST = {f"00:00:{n:02X}" for n in range(1, 11)}
BANNED = ("password", "passwd", "secret", "token", "changeme", "cisco123")
RFC5737 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
ROLE = "sw"
DEV_TYPE = "access"
OS = "IOS-XE"
PORT_COUNT = 48
MAX_NN = 254


def assert_demo_path(path: Path) -> None:
    if path.name in PRODUCTION_FILENAMES:
        raise SystemExit(f"refusing to write production filename {path.name}")
    if not path.name.startswith("stellar_express_"):
        raise SystemExit(f"showcase file must use stellar_express_ prefix: {path.name}")
    try:
        path.resolve().relative_to(PACK.resolve())
    except ValueError as exc:
        raise SystemExit(f"refusing to write outside fake_stellar/: {path}") from exc


def letters(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z]", "", text.lower())


def words(text: str) -> list[str]:
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii").lower()
    return re.findall(r"[a-z]+", text)


def location_token(city: str, admin1: str, used: set[str]) -> str:
    city_l = letters(city)
    admin_l = letters(admin1)
    city_words = words(city)
    initials = "".join(w[0] for w in city_words)
    candidates: list[str] = []
    if len(city_l) >= 3:
        candidates.append(city_l[:3])
    if len(city_l) >= 4:
        candidates.append(city_l[:4])
    if len(initials) >= 3:
        candidates.append(initials[:3])
    if len(initials) >= 4:
        candidates.append(initials[:4])
    if admin_l:
        for i in range(1, 4):
            for j in range(1, 4):
                if i + j in (3, 4) and len(city_l) >= i and len(admin_l) >= j:
                    candidates.append(city_l[:i] + admin_l[:j])
    seen: set[str] = set()
    for token in candidates:
        if token in seen or len(token) not in (3, 4):
            continue
        seen.add(token)
        if token not in used:
            return token
    base = (city_l + admin_l + "site")[:3]
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for n in (3, 4):
        prefix = base[: n - 1].ljust(n - 1, "x")
        for ch in alphabet:
            token = prefix + ch
            if token not in used:
                return token
    raise RuntimeError(f"no location token for {city!r}")


def admin1_folder(admin1: str, cc: str) -> str:
    if cc == "us":
        return admin1.replace(" ", "_")
    return cc


def site_name(city: str, admin1: str) -> str:
    return f"{city}, {admin1}" if admin1 else city


def switch_count(site_type: str) -> int:
    return {
        "regional": REGIONAL_SWITCHES,
        "branch": BRANCH_SWITCHES,
        "hq": HQ_SWITCHES,
        "dc": DC_SWITCHES,
    }[site_type]


def is_rfc5737(cidr: str) -> bool:
    ip_s = cidr.split("/", 1)[0]
    try:
        ip = ipaddress.ip_address(ip_s)
    except ValueError:
        return False
    return any(ip in net for net in RFC5737)


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    assert_demo_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns, lineterminator="\n", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise SystemExit(f"missing {path}")
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def is_trivial_nic_suffix(suffix: str) -> bool:
    parts = suffix.split(":")
    if len(parts) != 3:
        return True
    if suffix in TRIVIAL_LAST or suffix in {"00:00:00", "FF:FF:FF"}:
        return True
    a, b, c = (int(p, 16) for p in parts)
    if a == 0 and b == 0:
        return True
    if b == 0 and 1 <= c <= 10:
        return True
    return False


def nic_suffix(key: str, used: set[str]) -> str:
    n = 0
    while n < 4096:
        digest = hashlib.sha256(f"{STELLAR_SALT}|{key}|{n}".encode("utf-8")).digest()
        suffix = ":".join(f"{b:02X}" for b in digest[:3])
        if suffix not in used and not is_trivial_nic_suffix(suffix):
            used.add(suffix)
            return suffix
        n += 1
    raise SystemExit(f"could not allocate a NIC suffix for {key}")


def reserved_suffixes() -> set[str]:
    used: set[str] = set()
    for path in (LAB_ENDPOINTS, LIGHT_YAML, FULL_YAML):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for mac in re.findall(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", text):
            used.add(":".join(p.upper() for p in mac.split(":")[3:]))
    return used


def location_rows(sites: list[dict[str, str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = [
        {
            "ndg": "regional",
            "description": "Largest-city type folder.",
            "placeholder": "false",
            "parent": "",
        },
        {
            "ndg": "branch",
            "description": "Branch depot type folder.",
            "placeholder": "false",
            "parent": "",
        },
        {
            "ndg": "hq",
            "description": "World HQ type folder (Houston control campus).",
            "placeholder": "false",
            "parent": "",
        },
        {
            "ndg": "dc",
            "description": "Data-center type folder (Dallas fabric).",
            "placeholder": "false",
            "parent": "",
        },
    ]
    seen_parent: set[str] = set()
    for site in sites:
        parent = admin1_folder(site["admin1"], site["cc"])
        if parent not in seen_parent:
            seen_parent.add(parent)
            if site["cc"] == "us":
                desc = f"US state {site['admin1']}."
            else:
                desc = f"Country {site['cc']}."
            rows.append(
                {
                    "ndg": parent,
                    "description": desc,
                    "placeholder": "false",
                    "parent": "",
                }
            )
        rows.append(
            {
                "ndg": site["id"],
                "description": f"Site folder Location#All Locations#{parent}#{site['id']}",
                "placeholder": "false",
                "parent": parent,
            }
        )
    return rows


def build_sample_sites() -> list[dict[str, str]]:
    return [dict(s) for s in SHOWCASE_SITES]


def build_sample_devices(sites: list[dict[str, str]]) -> list[dict[str, str]]:
    by_id = {s["id"]: s for s in sites}
    devices: list[dict[str, str]] = []
    for site_id, (token, net, start, count) in SAMPLE_DEVICE_PLAN.items():
        site = by_id[site_id]
        for i in range(count):
            nn = i + 1
            octet = start + i
            devices.append(
                {
                    "hostname": f"{token}-sw-{nn:02d}",
                    "mgmt_ip": f"{net}.{octet}/32",
                    "site_code": site_id,
                    "site_name": site_name(site["city"], site["admin1"]),
                    "country_code": site["cc"],
                    "role": ROLE,
                    "type": DEV_TYPE,
                    "os": OS,
                    "port_count": str(PORT_COUNT),
                }
            )
    return devices


def build_sample_endpoints() -> list[dict[str, str]]:
    used = reserved_suffixes()
    rows: list[dict[str, str]] = []
    for group in LOCKED_GROUPS:
        oui, org = LOCKED_OUI[group]
        for seq in range(1, SAMPLE_MACS_PER_GROUP + 1):
            suffix = nic_suffix(f"sample|{group}|{seq}", used)
            rows.append(
                {
                    "mac": f"{oui}:{suffix}",
                    "endpoint_identity_group": group,
                    "oui": oui,
                    "organization": org,
                    "description": (
                        "Stellar Express sample MAC. Not hardware. "
                        f"IEEE MA-L OUI {oui} ({org})."
                    ),
                    "desk": "",
                    "switch": "",
                    "port": "",
                    "site": "",
                }
            )
    return rows


def load_city_catalog() -> list[dict[str, str]]:
    if not CITY_CATALOG.is_file():
        raise SystemExit(
            f"--full needs the public city catalog {CITY_CATALOG} "
            "(read-only; this script never writes it)"
        )
    with CITY_CATALOG.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != FULL_SITE_COUNT:
        raise SystemExit(f"city catalog expected {FULL_SITE_COUNT} rows, got {len(rows)}")
    out: list[dict[str, str]] = []
    for raw in rows:
        site_id = raw["id"]
        site_type = STELLAR_TYPE_OVERRIDES.get(site_id, raw["type"])
        out.append(
            {
                "id": site_id,
                "city": raw["city"],
                "admin1": raw["admin1"],
                "cc": raw["cc"],
                "type": site_type,
                "facility": FACILITY[site_type],
            }
        )
    return out


def build_full_devices(sites: list[dict[str, str]]) -> list[dict[str, str]]:
    used_by_cc: dict[str, set[str]] = defaultdict(set)
    devices: list[dict[str, str]] = []
    for site in sites:
        token = location_token(site["city"], site["admin1"], used_by_cc[site["cc"]])
        used_by_cc[site["cc"]].add(token)
        n_sw = switch_count(site["type"])
        if n_sw > MAX_NN:
            raise SystemExit(f"{site['id']} would exceed {MAX_NN} devices")
        net = DOC_NET[site["type"]]
        for nn in range(1, n_sw + 1):
            devices.append(
                {
                    "hostname": f"{site['cc']}{token}-sw-{nn:02d}",
                    "mgmt_ip": f"{net}.{nn}/32",
                    "site_code": site["id"],
                    "site_name": site_name(site["city"], site["admin1"]),
                    "country_code": site["cc"],
                    "role": ROLE,
                    "type": DEV_TYPE,
                    "os": OS,
                    "port_count": str(PORT_COUNT),
                }
            )
    return devices


def build_full_endpoints(devices: list[dict[str, str]]) -> list[dict[str, str]]:
    if len(devices) != FULL_DEVICE_COUNT:
        raise SystemExit(f"full endpoints need {FULL_DEVICE_COUNT} devices, got {len(devices)}")
    used = reserved_suffixes()
    rows: list[dict[str, str]] = []
    desk_n = 0
    for sw in devices[:DESK_SWITCH_COUNT]:
        for slot in range(1, DESKS_PER_SWITCH + 1):
            desk_n += 1
            did = f"desk-{desk_n:06d}"
            port = f"Gi1/0/{slot}"
            for group in ("Phones", "Windows"):
                oui, org = LOCKED_OUI[group]
                suffix = nic_suffix(f"full|{group}|{did}", used)
                rows.append(
                    {
                        "mac": f"{oui}:{suffix}",
                        "endpoint_identity_group": group,
                        "oui": oui,
                        "organization": org,
                        "description": "Stellar Express lab MAC. Not hardware. IEEE MA-L.",
                        "desk": did,
                        "switch": sw["hostname"],
                        "port": port,
                        "site": sw["site_code"],
                    }
                )
    nd_i = 0
    non_desk_switches = devices[-NON_DESK_TOTAL:]
    for group in NON_DESK_GROUPS:
        for seq in range(1, FULL_GROUP_COUNTS[group] + 1):
            sw = non_desk_switches[nd_i]
            oui, org = LOCKED_OUI[group]
            suffix = nic_suffix(f"full|{group}|infra|{seq:06d}", used)
            rows.append(
                {
                    "mac": f"{oui}:{suffix}",
                    "endpoint_identity_group": group,
                    "oui": oui,
                    "organization": org,
                    "description": "Stellar Express lab MAC. Not hardware. IEEE MA-L.",
                    "desk": "",
                    "switch": sw["hostname"],
                    "port": "Gi1/0/6",
                    "site": sw["site_code"],
                }
            )
            nd_i += 1
    if len(rows) != FULL_ENDPOINT_COUNT:
        raise SystemExit(f"internal full endpoint count {len(rows)} != {FULL_ENDPOINT_COUNT}")
    return rows


def blob_ok(rows: list[dict], columns: list[str]) -> None:
    for r in rows:
        packed = ",".join(str(r.get(c) or "") for c in columns).lower()
        for bad in BANNED:
            if bad in packed:
                raise SystemExit(f"banned string {bad!r} present")


def verify_sites(rows: list[dict[str, str]], expect: int | None) -> None:
    errors: list[str] = []
    if expect is not None and len(rows) != expect:
        errors.append(f"site count {len(rows)} != {expect}")
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)):
        errors.append("duplicate site ids")
    for r in rows:
        if r["type"] not in {"regional", "branch", "hq", "dc"}:
            errors.append(f"bad type {r['type']}")
            break
        if not re.fullmatch(r"[a-z]{2}", r["cc"]):
            errors.append(f"bad cc {r['cc']}")
            break
    blob_ok(rows, SITE_COLUMNS)
    if errors:
        raise SystemExit("site verify failed:\n  " + "\n  ".join(errors))


def verify_devices(
    rows: list[dict[str, str]],
    sites: list[dict[str, str]],
    *,
    expect: int | None,
    ips_globally_unique: bool,
) -> None:
    errors: list[str] = []
    if expect is not None and len(rows) != expect:
        errors.append(f"device count {len(rows)} != {expect}")
    hostnames = [r["hostname"] for r in rows]
    if len(hostnames) != len(set(hostnames)):
        errors.append("duplicate hostnames")
    site_ids = {s["id"] for s in sites}
    missing = {r["site_code"] for r in rows} - site_ids
    if missing:
        errors.append(f"site_code not in sites: {sorted(missing)[:5]}")
    ips = [r["mgmt_ip"] for r in rows]
    if ips_globally_unique and len(ips) != len(set(ips)):
        errors.append("sample device IPs must be unique")
    per_site_ips: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        if not is_rfc5737(r["mgmt_ip"]):
            errors.append(f"not RFC 5737: {r['mgmt_ip']}")
            break
        if r["role"] != ROLE or r["type"] != DEV_TYPE:
            errors.append(f"bad role/type {r['hostname']}")
            break
        per_site_ips[r["site_code"]].append(r["mgmt_ip"])
    for site_id, site_ips in per_site_ips.items():
        if len(site_ips) != len(set(site_ips)):
            errors.append(f"duplicate IPs at {site_id}")
            break
    blob_ok(rows, DEVICE_COLUMNS)
    if errors:
        raise SystemExit("device verify failed:\n  " + "\n  ".join(errors))


def verify_endpoints(rows: list[dict[str, str]], expect: int) -> None:
    errors: list[str] = []
    if len(rows) != expect:
        errors.append(f"endpoint count {len(rows)} != {expect}")
    macs = [r["mac"] for r in rows]
    if len(macs) != len(set(macs)):
        dup = [m for m, c in Counter(macs).items() if c > 1]
        errors.append(f"duplicate MACs: {dup[:5]}")
    per_group = Counter(r["endpoint_identity_group"] for r in rows)
    extra = set(per_group) - set(LOCKED_GROUPS)
    missing = set(LOCKED_GROUPS) - set(per_group)
    if extra:
        errors.append(f"unknown groups: {sorted(extra)}")
    if missing:
        errors.append(f"missing groups: {sorted(missing)}")
    for r in rows:
        mac = r["mac"]
        group = r["endpoint_identity_group"]
        oui, _org = LOCKED_OUI[group]
        if not MAC_RE.fullmatch(mac):
            errors.append(f"MAC not uppercase colon-hex: {mac}")
            break
        if mac.startswith("02:00:"):
            errors.append(f"02:00:GG pattern: {mac}")
            break
        if not mac.startswith(f"{oui}:"):
            errors.append(f"{group} MAC {mac} does not start with {oui}")
            break
        suffix = ":".join(mac.split(":")[3:])
        if is_trivial_nic_suffix(suffix):
            errors.append(f"trivial NIC suffix: {mac}")
            break
        if "not hardware" not in r["description"].casefold():
            errors.append(f"description must say not hardware: {mac}")
            break
        if "guest" in group.lower():
            errors.append("guest group")
            break
    blob_ok(rows, ENDPOINT_COLUMNS)
    if errors:
        raise SystemExit("endpoint verify failed:\n  " + "\n  ".join(errors))


def verify_locations(rows: list[dict[str, str]], sites: list[dict[str, str]]) -> None:
    names = {r["ndg"] for r in rows}
    errors: list[str] = []
    if len(names) != len(rows):
        errors.append("duplicate location ndg names")
    for r in rows:
        parent = (r.get("parent") or "").strip()
        if parent and parent not in names:
            errors.append(f"parent {parent!r} missing")
            break
    for site in sites:
        if site["id"] not in names:
            errors.append(f"site folder missing for {site['id']}")
            break
    if errors:
        raise SystemExit("location verify failed:\n  " + "\n  ".join(errors))


def verify_yaml(path: Path) -> None:
    if yaml is None:
        raise SystemExit("PyYAML is required to verify YAML")
    if not path.is_file():
        raise SystemExit(f"missing {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path.name} did not parse to a mapping")
    missing = [k for k in SCHEMA_KEYS if k not in data]
    if missing:
        raise SystemExit(f"{path.name} missing top-level keys: {missing}")
    extra = [k for k in data if k not in SCHEMA_KEYS]
    if extra:
        raise SystemExit(f"{path.name} unknown top-level keys: {extra}")

    def names(key: str, field: str) -> set[str]:
        return {str(row[field]) for row in (data.get(key) or []) if isinstance(row, dict)}

    errors: list[str] = []
    site_ids = names("sites", "id")
    ndgs = names("ndgs", "ndg")
    command_sets = names("command_sets", "name")
    shells = names("shell_profiles", "name")
    eigs = names("endpoint_identity_groups", "name")
    profiles = names("authorization_profiles", "name")
    protocols = names("allowed_protocols", "name")
    loc = names("location_ndgs", "ndg")
    authz_groups = names("tacacs_authz", "identity_group")

    if eigs != set(LOCKED_GROUPS):
        errors.append(f"endpoint groups {sorted(eigs)} != {list(LOCKED_GROUPS)}")
    for d in data.get("devices") or []:
        if d.get("site") not in site_ids:
            errors.append(f"device site {d.get('site')!r} missing")
        if not is_rfc5737(str(d.get("mgmt_ip") or "")):
            errors.append(f"device IP not RFC 5737: {d.get('mgmt_ip')}")
    for r in data.get("tacacs_authz") or []:
        if r.get("ndg") not in ndgs:
            errors.append(f"tacacs ndg {r.get('ndg')!r} missing")
        if r.get("command_set") not in command_sets:
            errors.append(f"command_set {r.get('command_set')!r} missing")
        if r.get("shell_profile") not in shells:
            errors.append(f"shell_profile {r.get('shell_profile')!r} missing")
    for u in data.get("users") or []:
        if u.get("identity_group") not in authz_groups:
            errors.append(f"user group {u.get('identity_group')!r} not in tacacs_authz")
        email = str(u.get("email") or "")
        if email and not email.endswith("@example.com"):
            errors.append(f"email not @example.com: {email}")
    for e in data.get("endpoints") or []:
        if e.get("endpoint_identity_group") not in eigs:
            errors.append(f"endpoint group {e.get('endpoint_identity_group')!r} missing")
        mac = str(e.get("mac") or "")
        if not MAC_RE.fullmatch(mac):
            errors.append(f"YAML MAC not uppercase colon-hex: {mac}")
    yaml_macs = [e["mac"] for e in data.get("endpoints") or []]
    if len(yaml_macs) != len(set(yaml_macs)):
        errors.append("duplicate YAML MACs")
    for r in data.get("network_access_authz") or []:
        if r.get("endpoint_identity_group") not in eigs:
            errors.append(f"authz group {r.get('endpoint_identity_group')!r} missing")
        if r.get("profile") not in profiles:
            errors.append(f"authz profile {r.get('profile')!r} missing")
    authz_eigs = {r.get("endpoint_identity_group") for r in data.get("network_access_authz") or []}
    if authz_eigs != set(LOCKED_GROUPS):
        errors.append("network_access_authz must cover all 11 groups")
    for ps in data.get("network_access_policy_sets") or []:
        if ps.get("service_name") not in protocols:
            errors.append(f"policy set service {ps.get('service_name')!r} missing")
    for loc_row in data.get("location_ndgs") or []:
        parent = loc_row.get("parent")
        if parent and parent not in loc:
            errors.append(f"location parent {parent!r} missing")
    def walk(obj) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in BANNED:
                    errors.append(f"banned key {k!r}")
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, str):
            low = obj.lower()
            # Comments that say secrets are absent are fine; values must not hold them.
            if any(p in low for p in ("not in this file", "no password", "secrets are not")):
                return
            for bad in BANNED:
                if bad in low:
                    errors.append(f"banned string {bad!r} in YAML value {obj!r}")
                    return

    walk(data)
    if errors:
        raise SystemExit(f"{path.name} cross-ref failed:\n  " + "\n  ".join(errors[:20]))


def print_sizes(paths: list[Path]) -> None:
    for path in paths:
        if path.is_file():
            size = path.stat().st_size
            print(f"  {path.relative_to(REPO)} {size} bytes ({size / (1024 * 1024):.2f} MiB)")
        else:
            print(f"  {path.relative_to(REPO)} MISSING")


def write_samples() -> None:
    sites = build_sample_sites()
    devices = build_sample_devices(sites)
    endpoints = build_sample_endpoints()
    locations = location_rows(sites)
    verify_sites(sites, 9)
    verify_devices(devices, sites, expect=29, ips_globally_unique=True)
    verify_endpoints(endpoints, SAMPLE_ENDPOINT_COUNT)
    verify_locations(locations, sites)
    write_csv(SITES_SAMPLE, SITE_COLUMNS, sites)
    write_csv(DEVICES_SAMPLE, DEVICE_COLUMNS, devices)
    write_csv(ENDPOINTS_SAMPLE, ENDPOINT_COLUMNS, endpoints)
    write_csv(LOCATION_SAMPLE, LOCATION_COLUMNS, locations)
    print("wrote stellar_express_*_sample.csv")
    print_sizes([SITES_SAMPLE, DEVICES_SAMPLE, ENDPOINTS_SAMPLE, LOCATION_SAMPLE])


def write_full() -> None:
    sites = load_city_catalog()
    devices = build_full_devices(sites)
    endpoints = build_full_endpoints(devices)
    locations = location_rows(sites)
    verify_sites(sites, FULL_SITE_COUNT)
    verify_devices(devices, sites, expect=FULL_DEVICE_COUNT, ips_globally_unique=False)
    verify_endpoints(endpoints, FULL_ENDPOINT_COUNT)
    verify_locations(locations, sites)
    write_csv(SITES_FULL, SITE_COLUMNS, sites)
    write_csv(DEVICES_FULL, DEVICE_COLUMNS, devices)
    write_csv(ENDPOINTS_FULL, ENDPOINT_COLUMNS, endpoints)
    write_csv(LOCATION_FULL, LOCATION_COLUMNS, locations)
    print("wrote stellar_express_*.csv (local --full; gitignored until CoS locks scale)")
    print_sizes([SITES_FULL, DEVICES_FULL, ENDPOINTS_FULL, LOCATION_FULL])
    ep_size = ENDPOINTS_FULL.stat().st_size
    if ep_size > 50 * 1024 * 1024:
        print(
            f"NOTE: {ENDPOINTS_FULL.name} is {ep_size} bytes (>50 MiB). "
            "Do not commit it. Attach a GitHub Release zip if CoS wants it published."
        )
    else:
        print(
            f"NOTE: {ENDPOINTS_FULL.name} is {ep_size} bytes. "
            "Still omitted from the PR until CoS locks scale. Release zip if needed."
        )


def verify_committed() -> None:
    sites = load_csv(SITES_SAMPLE)
    devices = load_csv(DEVICES_SAMPLE)
    endpoints = load_csv(ENDPOINTS_SAMPLE)
    locations = load_csv(LOCATION_SAMPLE)
    verify_sites(sites, 9)
    verify_devices(devices, sites, expect=29, ips_globally_unique=True)
    verify_endpoints(endpoints, SAMPLE_ENDPOINT_COUNT)
    verify_locations(locations, sites)
    verify_yaml(FULL_YAML)
    if LIGHT_YAML.is_file() and yaml is not None:
        light = yaml.safe_load(LIGHT_YAML.read_text(encoding="utf-8"))
        if not isinstance(light, dict) or "lab" not in light:
            raise SystemExit("light fake_ise_system.yaml looks damaged")
    print("verified stellar_express_*_sample.csv + fake_ise_system_full.yaml cross-refs")
    print_sizes([SITES_SAMPLE, DEVICES_SAMPLE, ENDPOINTS_SAMPLE, LOCATION_SAMPLE, FULL_YAML])
    if ENDPOINTS_FULL.is_file():
        full_ep = load_csv(ENDPOINTS_FULL)
        verify_endpoints(full_ep, FULL_ENDPOINT_COUNT)
        print(f"verified local --full endpoints ({len(full_ep)} rows)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full",
        action="store_true",
        help="Write production-ish stellar_express_*.csv locally (gitignored)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Check committed samples and YAML cross-refs; do not write",
    )
    parser.add_argument(
        "--samples",
        action="store_true",
        help="Write sample CSVs (default when neither --full nor --verify)",
    )
    args = parser.parse_args()
    if args.verify:
        verify_committed()
        return 0
    if args.full:
        write_full()
        return 0
    write_samples()
    return 0


if __name__ == "__main__":
    sys.exit(main())
