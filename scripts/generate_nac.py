#!/usr/bin/env python3
"""Build nac.yaml from the Excel CSVs. CSV stays the original Robert opens."""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

# ISE NDG leaf: alphanumeric, underscore, minus, dot. '#' is the path
# separator. Spaces/punctuation become underscore. Empty names are illegal.
_ISE_NDG_ILLEGAL = re.compile(r"[^A-Za-z0-9_.-]+")
_ISE_NDG_MULTI_US = re.compile(r"_+")
_ISE_NDG_LEAF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def ise_ndg_leaf(name: str) -> str:
    slug = _ISE_NDG_MULTI_US.sub("_", _ISE_NDG_ILLEGAL.sub("_", name.strip())).strip("_")
    if not slug or not _ISE_NDG_LEAF.fullmatch(slug):
        raise SystemExit(f"ISE NDG leaf name is illegal or empty: {name!r} -> {slug!r}")
    return slug

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "nac.yaml"


def read_csv(name: str) -> list[dict[str, str]]:
    with (ROOT / name).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def yq(value: str) -> str:
    if value == "":
        return '""'
    if (
        value.lower() in {"true", "false", "null", "yes", "no", "on", "off", "y", "n"}
        or value[0] in "-?:{}[],&*!|>%@`'\""
        or any(c in value for c in ":#{}[],&*!|>%@`'\"\\")
        or value.strip() != value
    ):
        return json.dumps(value, ensure_ascii=False)
    return value


def mapping(indent: int, items: list[tuple[str, str]], first_dash: bool = True) -> list[str]:
    pad = " " * indent
    lines = []
    for i, (k, v) in enumerate(items):
        prefix = f"{pad}- " if first_dash and i == 0 else f"{pad}  " if first_dash else pad
        if first_dash and i > 0:
            prefix = " " * (indent + 2)
        if first_dash and i == 0:
            lines.append(f"{pad}- {k}: {v}")
        elif first_dash:
            lines.append(f"{' ' * (indent + 2)}{k}: {v}")
        else:
            lines.append(f"{pad}{k}: {v}")
    return lines


def main() -> int:
    sites = read_csv("sites.csv")
    ndgs = read_csv("ndgs.csv")
    devices = read_csv("devices.csv")
    authc = read_csv("tacacs_authc.csv")
    authz = read_csv("tacacs_authz.csv")
    na_authc = read_csv("network_access_authc.csv")
    na_authz = read_csv("network_access_authz.csv")
    sample = read_csv("sample_nads.csv")
    # Lab 110 for nac.yaml / nac-validate only. Terraform apply reads
    # endpoints_enterprise.csv (see locals.tf). Do not fold 150k into this feed.
    endpoints = read_csv("endpoints.csv")
    users = read_csv("users.csv")

    if len(sites) != 400:
        raise SystemExit(f"sites.csv expected 400 rows, got {len(sites)}")
    if len(ndgs) != 4:
        raise SystemExit(f"ndgs.csv expected 4 rows, got {len(ndgs)}")
    if len(devices) != 15000:
        raise SystemExit(f"devices.csv expected 15000 rows, got {len(devices)}")
    if {d["role"] for d in devices} != {"sw"}:
        raise SystemExit("devices.csv has roles other than sw")

    try:
        import yaml
    except ImportError:
        raise SystemExit("PyYAML is required to read location_ndgs.yaml")
    loc_path = ROOT / "location_ndgs.yaml"
    loc_raw = yaml.safe_load(loc_path.read_text(encoding="utf-8")) or {}
    location_ndgs = loc_raw.get("location_ndgs") or []
    if not isinstance(location_ndgs, list) or not location_ndgs:
        raise SystemExit("location_ndgs.yaml must list type-level Location NDGs")
    if len(location_ndgs) > 8:
        raise SystemExit("location_ndgs.yaml has too many rows; type-level only")
    site_types = {s["type"].lower() for s in sites}
    loc_names = set()
    for row in location_ndgs:
        name = str(row.get("ndg", "")).lower()
        loc_names.add(name)
        placeholder = bool(row.get("placeholder"))
        desc = str(row.get("description", ""))
        if placeholder:
            if name in site_types:
                raise SystemExit(f"placeholder Location NDG {name} is tagged in sites.csv")
            if desc != "no sites tagged yet":
                raise SystemExit(f"placeholder Location NDG {name} description must be 'no sites tagged yet'")
        elif name not in site_types:
            raise SystemExit(f"Location NDG {name} has no sites in sites.csv")
    missing_types = site_types - loc_names
    if missing_types:
        raise SystemExit(f"sites.csv types missing from location_ndgs.yaml: {sorted(missing_types)}")
    for required in ("hq", "dc"):
        if required not in loc_names and required not in site_types:
            raise SystemExit(f"location_ndgs.yaml must include placeholder {required}")
    if any(t in {"hq", "dc"} for t in site_types):
        raise SystemExit("sites.yaml must not invent hq/dc city tags; types stay regional/branch")

    if any(k.lower() == "access" or k.lower().startswith("access_") for k in (devices[0].keys() if devices else [])):
        raise SystemExit("devices.csv must not have an Access column; Access is locked to access-marketing")

    # Naming lock: "regional" is ONLY the type-level NDG. US folder = slugged
    # admin1 (California). Non-US folder = cc. Never name a folder regional.
    # Site ISE path: Location#All Locations#{State}#{site_id}
    reserved_types = loc_names | {"regional", "branch", "hq", "dc"}
    site_folder_of: dict[str, str] = {}
    site_leaf_of: dict[str, str] = {}
    folder_meta: dict[str, dict[str, str]] = {}
    for row in sites:
        if row["cc"] == "us" and not (row.get("admin1") or "").strip():
            raise SystemExit(f"US site {row['id']} has no admin1 (state folder)")
        folder = ise_ndg_leaf(row["admin1"] if row["cc"] == "us" else row["cc"])
        leaf = ise_ndg_leaf(row["id"])
        if folder.lower() in reserved_types:
            raise SystemExit(
                f"Location folder {folder} must not reuse a type-level name "
                "(regional is the site-type NDG only; never a state folder)"
            )
        if leaf.lower() in reserved_types:
            raise SystemExit(f"site NDG {leaf} collides with a type-level Location NDG")
        if len(f"Location#All Locations#{folder}#{leaf}") > 100:
            raise SystemExit(f"ISE NDG path exceeds 100 chars: {row['id']}")
        site_folder_of[row["id"]] = folder
        site_leaf_of[row["id"]] = leaf
        if folder not in folder_meta:
            folder_meta[folder] = {
                "cc": row["cc"],
                "admin1": row["admin1"],
                "description": f"US state {row['admin1']}" if row["cc"] == "us" else f"Country {row['cc']}",
            }
        elif row["cc"] == "us" and folder_meta[folder]["admin1"] != row["admin1"]:
            raise SystemExit(f"state folder {folder} maps to more than one admin1")
        elif row["cc"] != "us" and folder_meta[folder]["cc"] != row["cc"]:
            raise SystemExit(f"country folder {folder} maps to more than one cc")

    if len(sample) != 8:
        raise SystemExit(f"sample_nads.csv expected 8 rows, got {len(sample)}")
    access_counts = Counter(r["access_ndg"] for r in sample)
    expect_access = {
        "access-marketing": 2,
        "access-hr": 2,
        "access-ceo": 2,
        "access-sourcecode": 2,
    }
    if access_counts != expect_access:
        raise SystemExit(f"sample_nads.csv must be 2 per Access NDG, got {dict(access_counts)}")
    host_to_site = {d["hostname"]: d["site_code"] for d in devices}
    site_type = {s["id"]: s["type"] for s in sites}
    sample_types = []
    for row in sample:
        host = row["hostname"]
        if host not in host_to_site:
            raise SystemExit(f"sample_nads.csv hostname not in devices.csv: {host}")
        sample_types.append(site_type[host_to_site[host]])
    if set(sample_types) != {"regional", "branch"}:
        raise SystemExit("sample NADs must span regional and branch site types")
    if any(t in {"hq", "dc"} for t in sample_types):
        raise SystemExit("sample NADs must not invent hq/dc site membership")

    locked_groups = (
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
    groups_path = ROOT / "endpoint_identity_groups.yaml"
    groups_raw = yaml.safe_load(groups_path.read_text(encoding="utf-8")) or {}
    group_names = [
        str(g["name"])
        for g in (groups_raw.get("endpoint_identity_groups") or [])
        if isinstance(g, dict) and g.get("name")
    ]
    if tuple(group_names) != locked_groups:
        raise SystemExit(f"endpoint_identity_groups.yaml must be {list(locked_groups)}, got {group_names}")
    if any(n in {"Workstation", "IP-Phone", "Printer"} for n in group_names):
        raise SystemExit("Workstation / IP-Phone / Printer groups are gone")
    if len(endpoints) != 110:
        raise SystemExit(f"endpoints.csv expected 110 lab MACs, got {len(endpoints)}")
    macs = [e["mac"] for e in endpoints]
    if len(macs) != len(set(macs)):
        raise SystemExit("endpoints.csv has duplicate MACs")
    per_group = Counter(e["endpoint_identity_group"] for e in endpoints)
    if any(per_group.get(n) != 10 for n in locked_groups):
        raise SystemExit(f"endpoints.csv must have 10 MACs per group, got {dict(per_group)}")
    locked_oui = {
        "Phones": "00:04:f2",
        "AP": "9c:e3:30",
        "Printers": "9c:7b:ef",
        "TVs": "64:1b:2f",
        "Badge_Readers": "00:30:8e",
        "Cameras": "00:40:8c",
        "UPS": "00:c0:b7",
        "Powerstrips": "00:0d:5d",
        "Linux": "00:c0:4f",
        "Windows": "10:e7:c6",
        "RFID_Readers": "00:16:25",
    }
    suffixes = [":".join(m.split(":")[3:]) for m in macs]
    if len(suffixes) != len(set(suffixes)):
        raise SystemExit("endpoints.csv last-3-octet suffixes must be unique across 110")
    for e in endpoints:
        mac = e["mac"]
        group = e["endpoint_identity_group"]
        if group not in locked_groups:
            raise SystemExit(f"endpoint group not in lock: {group}")
        if mac.startswith("02:00:"):
            raise SystemExit(f"dropped 02:00:GG pattern still present: {mac}")
        oui = locked_oui[group]
        if not mac.startswith(f"{oui}:"):
            raise SystemExit(f"{group} MAC {mac} does not start with locked IEEE OUI {oui}")
        if (e.get("oui") or "") != oui:
            raise SystemExit(f"{group} endpoints.csv oui must be {oui}")
        if not (e.get("organization") or "").strip():
            raise SystemExit(f"{group} endpoints.csv must cite IEEE organization")
        suffix = ":".join(mac.split(":")[3:])
        last = int(suffix.split(":")[-1], 16)
        mid = int(suffix.split(":")[1], 16)
        first_nic = int(suffix.split(":")[0], 16)
        if first_nic == 0 and mid == 0 and 1 <= last <= 10:
            raise SystemExit(f"do not use 00:00:01–00:00:0A NIC suffixes: {mac}")
        desc = (e.get("description") or "").casefold()
        if "lab" not in desc or "not hardware" not in desc:
            raise SystemExit(f"description must say lab / not hardware: {mac}")
    if any("guest" in (e.get("endpoint_identity_group") or "").lower() for e in endpoints):
        raise SystemExit("Guest endpoints are not in this phase")

    locked_idg = (
        "T1",
        "T2",
        "T3",
        "T4",
        "vendor",
        "contractor",
        "auditor-internal",
        "auditor-external",
    )
    authz_idg = {(row.get("identity_group") or "").strip() for row in authz}
    authz_idg.discard("")
    if len(users) != 8:
        raise SystemExit(f"users.csv expected 8 lab Internal Users, got {len(users)}")
    usernames = [u["username"] for u in users]
    if len(usernames) != len(set(usernames)):
        raise SystemExit("users.csv has duplicate usernames")
    user_groups = [u["identity_group"] for u in users]
    if tuple(user_groups) != locked_idg:
        raise SystemExit(f"users.csv identity_group order must be {list(locked_idg)}, got {user_groups}")
    if any(g not in authz_idg for g in user_groups):
        raise SystemExit("users.csv identity_group must match tacacs_authz.csv")
    if users and any("pass" in k.lower() for k in users[0].keys()):
        raise SystemExit("users.csv must not contain a password column")
    user_blob = ",".join(users[0].keys()) + "," + ",".join(v for u in users for v in u.values())
    if "password" in user_blob.lower():
        raise SystemExit("refusing to copy a password out of users.csv")

    lines: list[str] = [
        "# Generated ISE-as-code feed. Do not edit by hand.",
        "# Rebuild: python3 scripts/generate_nac.py",
        "# Excel originals: sites.csv ndgs.csv devices.csv tacacs_authc.csv tacacs_authz.csv sample_nads.csv endpoints.csv users.csv",
        "# Lab endpoints.csv only (110) in this YAML feed. Terraform apply reads endpoints_enterprise.csv (endpoint_count default 150000).",
        "# TACACS objects: command_sets.yaml shell_profiles.yaml",
        "# Network Access: endpoint_identity_groups.yaml endpoints.yaml allowed_protocols.yaml authorization_profiles.yaml",
        "#   network_access.yaml network_access_authc.csv network_access_authz.csv",
        "# Internal Users: users.yaml (8 lab users; secrets stay in env)",
        "# Location NDGs: type-level in location_ndgs.yaml; state/city from sites.yaml",
        "",
        "lab:",
        "  pan:",
        "    count: 1",
        "    hostname: pan1",
        "    datastore: M4 / Ripper4-1",
        "    network: vmwarenet",
        "    cpu_reservation: false",
        "    memory_reservation: false",
        "    ova: Cisco-vISE-300-3.5.0.527.ova",
        "",
        "ndgs:",
    ]
    for row in ndgs:
        lines.extend(
            mapping(
                2,
                [
                    ("ndg", yq(row["ndg"])),
                    ("description", yq(row["description"])),
                    ("min_tier", yq(row["min_tier"])),
                ],
            )
        )

    lines.append("")
    lines.append("location_ndgs:")
    for row in location_ndgs:
        lines.extend(
            mapping(
                2,
                [
                    ("ndg", yq(str(row["ndg"]))),
                    ("description", yq(str(row["description"]))),
                    ("placeholder", "true" if row.get("placeholder") else "false"),
                ],
            )
        )
    for folder in sorted(folder_meta, key=lambda n: (folder_meta[n]["cc"] != "us", n)):
        meta = folder_meta[folder]
        lines.extend(
            mapping(
                2,
                [
                    ("ndg", yq(folder)),
                    ("description", yq(meta["description"])),
                    ("placeholder", "false"),
                ],
            )
        )
    for row in sites:
        desc = f"{row['city']}, {row['admin1']}" if row.get("admin1") else row["city"]
        lines.extend(
            mapping(
                2,
                [
                    ("ndg", yq(site_leaf_of[row["id"]])),
                    ("description", yq(desc)),
                    ("placeholder", "false"),
                    ("parent", yq(site_folder_of[row["id"]])),
                ],
            )
        )

    lines.append("")
    lines.append("sites:")
    for row in sites:
        lines.extend(
            mapping(
                2,
                [
                    ("id", yq(row["id"])),
                    ("city", yq(row["city"])),
                    ("admin1", yq(row["admin1"])),
                    ("cc", yq(row["cc"])),
                    ("type", yq(row["type"])),
                ],
            )
        )

    lines.append("")
    lines.append("tacacs_authc:")
    for row in authc:
        lines.extend(
            mapping(
                2,
                [
                    ("order", row["order"]),
                    ("name", yq(row["name"])),
                    ("protocol", yq(row["protocol"])),
                    ("identity_source", yq(row["identity_source"])),
                    ("if_auth_fail", yq(row["if_auth_fail"])),
                    ("if_user_not_found", yq(row["if_user_not_found"])),
                    ("if_process_fail", yq(row["if_process_fail"])),
                ],
            )
        )

    lines.append("")
    lines.append("tacacs_authz:")
    for row in authz:
        lines.extend(
            mapping(
                2,
                [
                    ("order", row["order"]),
                    ("name", yq(row["name"])),
                    ("identity_group", yq(row["identity_group"])),
                    ("ndg", yq(row["ndg"])),
                    ("command_set", yq(row["command_set"].replace("-", "_"))),
                    ("shell_profile", yq(row["shell_profile"].replace("-", "_"))),
                    ("time_bound", yq(row["time_bound"])),
                ],
            )
        )

    lines.append("")
    lines.append("network_access_authc:")
    for row in na_authc:
        lines.extend(
            mapping(
                2,
                [
                    ("order", row["order"]),
                    ("name", yq(row["name"])),
                    ("protocol", yq(row["protocol"])),
                    ("identity_source", yq(row["identity_source"])),
                    ("if_auth_fail", yq(row["if_auth_fail"])),
                    ("if_user_not_found", yq(row["if_user_not_found"])),
                    ("if_process_fail", yq(row["if_process_fail"])),
                    ("condition_dictionary_name", yq(row["condition_dictionary_name"])),
                    ("condition_attribute_name", yq(row["condition_attribute_name"])),
                    ("condition_operator", yq(row["condition_operator"])),
                    ("condition_attribute_value", yq(row["condition_attribute_value"])),
                ],
            )
        )

    lines.append("")
    lines.append("network_access_authz:")
    for row in na_authz:
        lines.extend(
            mapping(
                2,
                [
                    ("order", row["order"]),
                    ("name", yq(row["name"])),
                    ("endpoint_identity_group", yq(row["endpoint_identity_group"])),
                    ("profile", yq(row["profile"])),
                ],
            )
        )

    # TACACS objects. YAML originals: command_sets.yaml, shell_profiles.yaml.
    # Network Access objects: groups, allowed protocols, authz profiles, policy set.
    for extra in (
        "command_sets.yaml",
        "shell_profiles.yaml",
        "endpoint_identity_groups.yaml",
        "endpoints.yaml",
        "allowed_protocols.yaml",
        "authorization_profiles.yaml",
        "network_access.yaml",
        "users.yaml",
    ):
        body = (ROOT / extra).read_text(encoding="utf-8").rstrip()
        if body:
            lines.append("")
            lines.append(body)

    lines.append("")
    lines.append("devices:")
    for row in devices:
        lines.extend(
            mapping(
                2,
                [
                    ("hostname", yq(row["hostname"])),
                    ("site", yq(row["site_code"])),
                    ("mgmt_ip", yq(row["mgmt_ip"])),
                    ("role", yq(row["role"])),
                    ("type", "access"),
                ],
            )
        )
    lines.append("")

    text = "\n".join(lines)
    if "password" in text.lower():
        raise SystemExit("refusing to write password into nac.yaml")

    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {text.count(chr(10))+1} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
