#!/usr/bin/env python3
"""Build users.csv and users.yaml: 8 lab Internal Users for TACACS identity groups.

CoS lock: one lab user per existing TACACS identity group
(T1, T2, T3, T4, vendor, contractor, auditor-internal, auditor-external).
Not 150k. Not 300k. CSV can grow later if CoS bumps TARGET_COUNT.

Secrets stay in env (USER_PASSWORD_DEFAULT / TF_VAR_user_password).
This generator never writes a password column or value.

Identity group names match tacacs_authz.csv (hyphens on auditor-* stay).
Do not invent auditor_internal / auditor_external with underscores.

Rebuild:
  python3 scripts/generate_users.py
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHZ_CSV = ROOT / "tacacs_authz.csv"
USERS_CSV = ROOT / "users.csv"
USERS_YAML = ROOT / "users.yaml"

# Live ISE user identity groups from tacacs_authz.csv. Hyphens stay.
LOCKED_GROUPS = (
    "T1",
    "T2",
    "T3",
    "T4",
    "vendor",
    "contractor",
    "auditor-internal",
    "auditor-external",
)
TARGET_COUNT = len(LOCKED_GROUPS)
COLUMNS = [
    "username",
    "identity_group",
    "first_name",
    "last_name",
    "email",
    "enabled",
    "description",
]
BANNED = ("password", "passwd", "secret", "token", "changeme", "cisco123")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


def load_authz_groups() -> set[str]:
    if not AUTHZ_CSV.is_file():
        raise SystemExit(f"missing {AUTHZ_CSV}")
    with AUTHZ_CSV.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    groups = {(row.get("identity_group") or "").strip() for row in rows}
    groups.discard("")
    missing = [g for g in LOCKED_GROUPS if g not in groups]
    extra_ok = groups - set(LOCKED_GROUPS)
    if missing:
        raise SystemExit(
            f"tacacs_authz.csv missing identity groups {missing}. "
            "Do not invent groups; join the existing TACACS set."
        )
    if extra_ok:
        # Authz may only use the locked set today; fail if a new group appears
        # without a lab user (generator is the lock).
        raise SystemExit(
            f"tacacs_authz.csv has identity groups not in the lab user lock: "
            f"{sorted(extra_ok)}. Bump LOCKED_GROUPS / TARGET_COUNT if CoS added one."
        )
    return groups


def build() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for group in LOCKED_GROUPS:
        slug = group.lower()
        username = f"lab-{slug}"
        last = group.replace("-", " ").title().replace(" ", "")
        rows.append(
            {
                "username": username,
                "identity_group": group,
                "first_name": "Lab",
                "last_name": last,
                "email": f"{username}@test.lab",
                "enabled": "true",
                "description": (
                    f"Lab Internal User for TACACS identity group {group}. "
                    "Not a production account."
                ),
            }
        )
    return rows


def verify(rows: list[dict[str, str]], authz_groups: set[str]) -> None:
    errors: list[str] = []
    if len(rows) != TARGET_COUNT:
        errors.append(f"row count {len(rows)} != {TARGET_COUNT}")
    if TARGET_COUNT >= 150000 or len(rows) >= 150000:
        errors.append("do not dump 150k users in this PR")
    names = [r["username"] for r in rows]
    if len(names) != len(set(names)):
        dup = [n for n, c in Counter(names).items() if c > 1]
        errors.append(f"duplicate usernames: {dup[:5]}")
    groups = [r["identity_group"] for r in rows]
    if tuple(groups) != LOCKED_GROUPS:
        errors.append(f"identity_group order must be {list(LOCKED_GROUPS)}, got {groups}")
    for g in groups:
        if g not in authz_groups:
            errors.append(f"identity_group {g!r} is not a TACACS identity group")
    per_group = Counter(groups)
    for name in LOCKED_GROUPS:
        if per_group.get(name) != 1:
            errors.append(f"{name} has {per_group.get(name)} users, want 1")
    for r in rows:
        if list(r.keys()) != COLUMNS:
            errors.append(f"columns must be {COLUMNS}, got {list(r.keys())}")
            break
        if any(c.lower() in BANNED or "pass" in c.lower() for c in r):
            errors.append("CSV must not contain a password/secret column")
            break
        if not USERNAME_RE.fullmatch(r["username"]):
            errors.append(f"illegal username: {r['username']!r}")
        if r["enabled"] != "true":
            errors.append(f"{r['username']} enabled must be true")
        if r["identity_group"] not in r["description"]:
            errors.append(f"{r['username']} description must cite identity group")
        if "lab" not in r["description"].casefold():
            errors.append(f"{r['username']} description must say lab")
        blob = ",".join(r.values()).casefold()
        for bad in BANNED:
            if bad in blob:
                errors.append(f"banned string {bad!r} in {r['username']}")
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
    with USERS_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def write_yaml(rows: list[dict[str, str]]) -> None:
    # Do not mention the substring "password" here: generate_nac.py concatenates
    # this file into nac.yaml and refuses that word.
    lines = [
        "# Generated lab Internal Users. Do not edit by hand.",
        "# Rebuild: python3 scripts/generate_users.py",
        "# One lab user per TACACS identity group (8). Not 150k. Not 300k.",
        "# Groups match tacacs_authz.csv: T1 T2 T3 T4 vendor contractor",
        "#   auditor-internal auditor-external (hyphens stay).",
        "# CiscoDevNet/ise 0.3.4 ise_internal_user. Secrets stay in env.",
        "# https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/internal_user",
        "users:",
    ]
    for r in rows:
        lines.append(f"  - username: {yaml_scalar(r['username'])}")
        lines.append(f"    identity_group: {yaml_scalar(r['identity_group'])}")
        lines.append(f"    first_name: {yaml_scalar(r['first_name'])}")
        lines.append(f"    last_name: {yaml_scalar(r['last_name'])}")
        lines.append(f"    email: {yaml_scalar(r['email'])}")
        lines.append(f"    enabled: {r['enabled']}")
        lines.append(f"    description: {yaml_scalar(r['description'])}")
    lines.append("")
    USERS_YAML.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    authz_groups = load_authz_groups()
    rows = build()
    verify(rows, authz_groups)
    write_csv(rows)
    write_yaml(rows)
    print(f"wrote {USERS_CSV} ({len(rows)} lab Internal Users)")
    print(f"wrote {USERS_YAML}")
    print(f"groups={list(LOCKED_GROUPS)}")
    print(f"sample {rows[0]['username']} -> {rows[0]['identity_group']}")
    print(f"last   {rows[-1]['username']} -> {rows[-1]['identity_group']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
