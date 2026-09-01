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
    sample = read_csv("sample_nads.csv")

    if len(sites) != 400:
        raise SystemExit(f"sites.csv expected 400 rows, got {len(sites)}")
    if len(ndgs) != 4:
        raise SystemExit(f"ndgs.csv expected 4 rows, got {len(ndgs)}")
    if len(devices) != 6250:
        raise SystemExit(f"devices.csv expected 6250 rows, got {len(devices)}")
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

    # One Location NDG per site. ISE: Location#All Locations#{site_id}
    # site_id is already ISE-legal ([a-z0-9-]+); sanitize if not, fail if empty.
    site_leaf_of: dict[str, str] = {}
    for row in sites:
        leaf = ise_ndg_leaf(row["id"])
        if leaf.lower() in loc_names:
            raise SystemExit(f"site NDG {leaf} collides with a type-level Location NDG")
        if len(f"Location#All Locations#{leaf}") > 100:
            raise SystemExit(f"ISE NDG path exceeds 100 chars: {row['id']}")
        site_leaf_of[row["id"]] = leaf

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

    lines: list[str] = [
        "# Generated ISE-as-code feed. Do not edit by hand.",
        "# Rebuild: python3 scripts/generate_nac.py",
        "# Excel originals: sites.csv ndgs.csv devices.csv tacacs_authc.csv tacacs_authz.csv sample_nads.csv",
        "# TACACS objects: command_sets.yaml shell_profiles.yaml",
        "# Location NDGs: type-level in location_ndgs.yaml; one site NDG per sites.yaml id",
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
    for row in sites:
        desc = f"{row['city']}, {row['admin1']}" if row.get("admin1") else row["city"]
        lines.extend(
            mapping(
                2,
                [
                    ("ndg", yq(site_leaf_of[row["id"]])),
                    ("description", yq(desc)),
                    ("placeholder", "false"),
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

    # TACACS objects. YAML originals: command_sets.yaml, shell_profiles.yaml.
    for extra in ("command_sets.yaml", "shell_profiles.yaml"):
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
