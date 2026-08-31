#!/usr/bin/env python3
"""Build devices.csv: 6,250 access switches from sites.csv.

Locked math: 150,000 users, phone+PC per user, 48-port switch => 24 users
per switch => 150000/24 = 6250 switches.

Regional sites get 20 switches; branch sites get 15.
50*20 + 350*15 = 6250.

Hostname: {cc}{site}-{role}-{nn} with role=sw and a 3-4 char site token
derived from the city (unique per country_code). site_code is the sites.csv
id so every row joins to a real site.

Loopback: 10.{country_id}.{site_id}.{nn}/32
US has 300 sites, so it uses two /16s (country_id 1 and 2); other countries
get one /16. site_id is 1-254 inside each /16.
"""

from __future__ import annotations

import csv
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITES_CSV = ROOT / "sites.csv"
DEVICES_CSV = ROOT / "devices.csv"

ROLE = "sw"
OS = "IOS-XE"
PORT_COUNT = 48
USERS_PER_SWITCH = 24
REGIONAL_SWITCHES = 20
BRANCH_SWITCHES = 15
TARGET_SWITCHES = 6250
MAX_SITE_ID = 254
MAX_NN = 254
COLUMNS = [
    "hostname",
    "mgmt_ip",
    "site_code",
    "site_name",
    "country_code",
    "country_id",
    "site_id",
    "role",
    "os",
    "port_count",
    "users_served",
]


def letters(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z]", "", text.lower())


def words(text: str) -> list[str]:
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii").lower()
    return re.findall(r"[a-z]+", text)


def location_token(city: str, admin1: str, used: set[str]) -> str:
    """3-4 char location for hostname, unique among `used` in this country."""
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
    if len(initials) == 2:
        for extra in city_l + admin_l:
            token = initials + extra
            if len(token) >= 3:
                candidates.append(token[:3])
            if len(token) >= 4:
                candidates.append(token[:4])
    for n in (3, 4):
        if len(city_l) >= n:
            for i in range(0, len(city_l) - n + 1):
                candidates.append(city_l[i : i + n])
    if admin_l:
        for i in range(1, 4):
            for j in range(1, 4):
                if i + j in (3, 4) and len(city_l) >= i and len(admin_l) >= j:
                    candidates.append(city_l[:i] + admin_l[:j])
        if len(admin_l) >= 3:
            candidates.append(admin_l[:3])
        if len(admin_l) >= 4:
            candidates.append(admin_l[:4])

    seen_cand = set()
    for token in candidates:
        if token in seen_cand or len(token) not in (3, 4):
            continue
        seen_cand.add(token)
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
        for ch1 in alphabet:
            for ch2 in alphabet:
                token = (base[: n - 2].ljust(n - 2, "x") + ch1 + ch2)[:n]
                if len(token) == n and token not in used:
                    return token
    raise RuntimeError(f"no location token for {city!r} / {admin1!r}")


def site_name(city: str, admin1: str) -> str:
    if admin1:
        return f"{city}, {admin1}"
    return city


def load_sites() -> list[dict[str, str]]:
    with SITES_CSV.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != 400:
        raise SystemExit(f"expected 400 sites, got {len(rows)}")
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate site ids")
    return rows


def assign_ids(sites: list[dict[str, str]]) -> None:
    """Numeric country_id (/16) and site_id (/24). US needs two /16s."""
    country_id = 0
    per_block = 0
    prev_cc = None
    for row in sites:
        cc = row["cc"]
        if cc != prev_cc or per_block >= MAX_SITE_ID:
            country_id += 1
            if country_id > MAX_SITE_ID:
                raise SystemExit("country_id overflow")
            per_block = 0
            prev_cc = cc
        per_block += 1
        row["country_id"] = country_id
        row["site_id"] = per_block


def assign_locations(sites: list[dict[str, str]]) -> None:
    used_by_cc: dict[str, set[str]] = defaultdict(set)
    for row in sites:
        token = location_token(row["city"], row["admin1"], used_by_cc[row["cc"]])
        used_by_cc[row["cc"]].add(token)
        row["location"] = token


def switch_count(site_type: str) -> int:
    if site_type == "regional":
        return REGIONAL_SWITCHES
    if site_type == "branch":
        return BRANCH_SWITCHES
    raise SystemExit(f"unknown site type {site_type!r}; not assigning extra HQ/DC")


def build_devices(sites: list[dict[str, str]]) -> list[dict]:
    devices = []
    for site in sites:
        n_sw = switch_count(site["type"])
        if n_sw > MAX_NN:
            raise SystemExit(f"{site['id']} would exceed {MAX_NN} devices")
        for nn in range(1, n_sw + 1):
            hostname = f"{site['cc']}{site['location']}-{ROLE}-{nn:02d}"
            mgmt_ip = f"10.{site['country_id']}.{site['site_id']}.{nn}/32"
            devices.append(
                {
                    "hostname": hostname,
                    "mgmt_ip": mgmt_ip,
                    "site_code": site["id"],
                    "site_name": site_name(site["city"], site["admin1"]),
                    "country_code": site["cc"],
                    "country_id": site["country_id"],
                    "site_id": site["site_id"],
                    "role": ROLE,
                    "os": OS,
                    "port_count": PORT_COUNT,
                    "users_served": USERS_PER_SWITCH,
                }
            )
    return devices


def verify(sites: list[dict[str, str]], devices: list[dict]) -> None:
    site_ids = {s["id"] for s in sites}
    errors = []
    if len(devices) != TARGET_SWITCHES:
        errors.append(f"switch count {len(devices)} != {TARGET_SWITCHES}")
    hostnames = [d["hostname"] for d in devices]
    ips = [d["mgmt_ip"] for d in devices]
    if len(hostnames) != len(set(hostnames)):
        dup = [h for h, c in Counter(hostnames).items() if c > 1]
        errors.append(f"duplicate hostnames: {dup[:5]}")
    if len(ips) != len(set(ips)):
        dup = [i for i, c in Counter(ips).items() if c > 1]
        errors.append(f"duplicate mgmt_ips: {dup[:5]}")
    missing = {d["site_code"] for d in devices} - site_ids
    if missing:
        errors.append(f"site_code not in sites.csv: {sorted(missing)[:5]}")
    per_site = Counter(d["site_code"] for d in devices)
    over = {k: v for k, v in per_site.items() if v > MAX_NN}
    if over:
        errors.append(f"site exceeds {MAX_NN} devices: {over}")
    users = sum(int(d["users_served"]) for d in devices)
    if users != TARGET_SWITCHES * USERS_PER_SWITCH:
        errors.append(f"users_served sum {users}")
    for d in devices:
        expect = f"10.{d['country_id']}.{d['site_id']}.{int(d['hostname'].rsplit('-', 1)[-1])}/32"
        if d["mgmt_ip"] != expect:
            errors.append(f"ip mismatch {d['hostname']} {d['mgmt_ip']} != {expect}")
            break
        nn = int(d["hostname"].rsplit("-", 1)[-1])
        cid, sid = int(d["country_id"]), int(d["site_id"])
        if not (1 <= cid <= MAX_SITE_ID and 1 <= sid <= MAX_SITE_ID and 1 <= nn <= MAX_NN):
            errors.append(f"octet out of range {d['hostname']} {d['mgmt_ip']}")
            break
        if d["role"] != ROLE or d["os"] != OS:
            errors.append(f"bad role/os {d}")
            break
        if int(d["port_count"]) != PORT_COUNT or int(d["users_served"]) != USERS_PER_SWITCH:
            errors.append(f"bad port/users {d}")
            break
        if d["country_code"] not in d["hostname"]:
            # hostname starts with cc
            if not d["hostname"].startswith(d["country_code"]):
                errors.append(f"hostname cc mismatch {d['hostname']} {d['country_code']}")
                break
    regional = {s["id"] for s in sites if s["type"] == "regional"}
    branch = {s["id"] for s in sites if s["type"] == "branch"}
    if any(per_site[s] != REGIONAL_SWITCHES for s in regional):
        errors.append("regional switch count mismatch")
    if any(per_site[s] != BRANCH_SWITCHES for s in branch):
        errors.append("branch switch count mismatch")
    if REGIONAL_SWITCHES <= BRANCH_SWITCHES:
        errors.append("regional must have more switches than branch")
    banned = ("192.168.1.90", "C!sco123", "password", "token", "admin")
    blob = ",".join(f"{d['hostname']},{d['mgmt_ip']}" for d in devices).lower()
    for bad in banned:
        if bad.lower() in blob:
            errors.append(f"banned string present: {bad}")
    if errors:
        raise SystemExit("verification failed:\n  " + "\n  ".join(errors))


def write_csv(devices: list[dict]) -> None:
    with DEVICES_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(devices)


def main() -> int:
    sites = load_sites()
    assign_ids(sites)
    assign_locations(sites)
    devices = build_devices(sites)
    verify(sites, devices)
    write_csv(devices)
    # file-level checks after write
    lines = DEVICES_CSV.read_text(encoding="utf-8-sig").splitlines()
    if len(lines) != TARGET_SWITCHES + 1:
        raise SystemExit(f"wc -l expected {TARGET_SWITCHES + 1}, got {len(lines)}")
    print(f"wrote {DEVICES_CSV} ({len(lines)} lines, {len(devices)} switches)")
    print(f"users_served sum={sum(int(d['users_served']) for d in devices)}")
    print(f"regional={REGIONAL_SWITCHES} branch={BRANCH_SWITCHES}")
    us_blocks = sorted({s['country_id'] for s in sites if s['cc'] == 'us'})
    print(f"us country_id blocks={us_blocks}")
    sample = next(d for d in devices if d["site_code"] == "us-new-york")
    print(f"sample {sample['hostname']} {sample['mgmt_ip']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
