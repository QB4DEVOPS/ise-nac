#!/usr/bin/env python3
"""Build nac.yaml from the Excel CSVs. CSV stays the original Robert opens."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

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

    if len(sites) != 400:
        raise SystemExit(f"sites.csv expected 400 rows, got {len(sites)}")
    if len(ndgs) != 4:
        raise SystemExit(f"ndgs.csv expected 4 rows, got {len(ndgs)}")
    if len(devices) != 6250:
        raise SystemExit(f"devices.csv expected 6250 rows, got {len(devices)}")
    if {d["role"] for d in devices} != {"sw"}:
        raise SystemExit("devices.csv has roles other than sw")

    lines: list[str] = [
        "# Generated ISE-as-code feed. Do not edit by hand.",
        "# Rebuild: python3 scripts/generate_nac.py",
        "# Excel originals: sites.csv ndgs.csv devices.csv tacacs_authc.csv tacacs_authz.csv",
        "# TACACS objects: command_sets.yaml shell_profiles.yaml",
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
