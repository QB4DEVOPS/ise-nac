"""FAIL unless lab Internal Users match the TACACS identity-group lock.

users.csv / users.yaml are the Git source of truth. Terraform POSTs
ise_internal_user (CiscoDevNet/ise 0.3.4). Secrets stay in env.
Lab is 8 users (one per TACACS identity group). Not 150k. Not 300k.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from nac_validate import RuleBase, Violation

_ROOT = Path(__file__).resolve().parents[1]
_USERS_YAML = _ROOT / "users.yaml"
_USERS_CSV = _ROOT / "users.csv"
_USERS_TF = _ROOT / "users.tf"
_VARS_TF = _ROOT / "variables.tf"
_MAIN_TF = _ROOT / "main.tf"
_LOCALS_TF = _ROOT / "locals.tf"
_ENV_EXAMPLE = _ROOT / ".env.example"
_LOAD_ENV = _ROOT / "load-env.ps1"
_AUTHZ_CSV = _ROOT / "tacacs_authz.csv"
_GEN = _ROOT / "scripts" / "generate_users.py"

_LOCKED_GROUPS = (
    "T1",
    "T2",
    "T3",
    "T4",
    "vendor",
    "contractor",
    "auditor-internal",
    "auditor-external",
)
_USER_TOTAL = len(_LOCKED_GROUPS)
_BANNED = ("password", "passwd", "secret", "token", "changeme", "cisco123")
_USER_RES = re.compile(r'resource\s+"ise_internal_user"\s+')
_WRONG_RES = re.compile(r'resource\s+"ise_user"\s+')
_USER_DEFAULT = re.compile(r'variable\s+"user_count"[\s\S]*?default\s+=\s+8', re.M)
_ENDPOINT_DEFAULT = re.compile(r'variable\s+"endpoint_count"[\s\S]*?default\s+=\s+110', re.M)
_NAD_DEFAULT = re.compile(r'variable\s+"nad_count"[\s\S]*?default\s+=\s+15000', re.M)
_IDG_RES = re.compile(r'resource\s+"ise_user_identity_group"\s+')
_PROVIDER = re.compile(r'source\s+=\s+"CiscoDevNet/ise"')
_PROVIDER_VER = re.compile(r'version\s+=\s+"~> 0\.3\.4"')


def _load_yaml(path: Path, key: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows = raw.get(key) or []
    return [r for r in rows if isinstance(r, dict)]


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


class Rule(RuleBase):
    id = "108"
    description = (
        "FAIL unless users.csv/users.yaml is 8 lab Internal Users wired to "
        "existing TACACS identity groups, Terraform uses ise_internal_user "
        "0.3.4, and secrets stay in env."
    )
    severity = "HIGH"
    title = "LAB INTERNAL USERS MUST MATCH TACACS IDENTITY GROUPS"
    affected_items_label = "Internal Users"
    explanation = """\
ISE ERS creates one Internal User per POST (ise_internal_user). The
Internal Users store max is 300,000; this repo ships a lab CSV of 8
(one per TACACS identity group). Identity groups stay T1–T4, vendor,
contractor, auditor-internal, auditor-external (hyphens). Secrets are
USER_PASSWORD_DEFAULT / TF_VAR_user_password, never Git."""
    recommendation = """\
Rebuild with python3 scripts/generate_users.py. Keep user_count default
8. Skip users with TF_VAR_user_count=0. Do not invent 150k rows. Do not
put secrets in users.csv."""
    references = [
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/internal_user",
        "https://developer.cisco.com/docs/identity-services-engine/latest/create-user/",
        "https://www.cisco.com/c/en/us/td/docs/security/ise/performance_and_scalability/b_ise_perf_and_scale.html",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []

        def add(message: str, path: str, name: str = "") -> None:
            violations.append(
                Violation(
                    message=message,
                    path=path,
                    details={"name": name or path, "kind": "internal_user", "source": path},
                )
            )

        yaml_rows = _load_yaml(_USERS_YAML, "users")
        csv_rows = _load_csv(_USERS_CSV)
        authz = _load_csv(_AUTHZ_CSV)
        authz_groups = {(r.get("identity_group") or "").strip() for r in authz}
        authz_groups.discard("")

        if not _USERS_CSV.is_file():
            add("users.csv is missing (Git source of truth for Internal Users).", "users.csv")
        if not _USERS_YAML.is_file():
            add("users.yaml is missing. Rebuild: python3 scripts/generate_users.py", "users.yaml")
        if not _GEN.is_file():
            add("scripts/generate_users.py is missing.", "scripts/generate_users.py")

        if len(csv_rows) != _USER_TOTAL:
            add(
                f"users.csv must contain {_USER_TOTAL} lab Internal Users "
                f"(one per TACACS identity group), got {len(csv_rows)}. Not 150k.",
                "users.csv",
            )
        if len(yaml_rows) != _USER_TOTAL:
            add(
                f"users.yaml must contain {_USER_TOTAL} lab Internal Users, "
                f"got {len(yaml_rows)}.",
                "users.yaml",
            )

        csv_names = [r.get("username", "") for r in csv_rows]
        if len(csv_names) != len(set(csv_names)):
            add("users.csv usernames must be unique.", "users.csv")
        yaml_names = [str(r.get("username", "")) for r in yaml_rows]
        if csv_names and yaml_names and csv_names != yaml_names:
            add("users.csv and users.yaml usernames must match in order.", "users.yaml")

        csv_groups = [r.get("identity_group", "") for r in csv_rows]
        if tuple(csv_groups) != _LOCKED_GROUPS:
            add(
                "users.csv identity_group order must be T1, T2, T3, T4, vendor, "
                f"contractor, auditor-internal, auditor-external (got {csv_groups}). "
                "Hyphens stay; do not invent auditor_internal.",
                "users.csv",
            )
        missing = [g for g in _LOCKED_GROUPS if g not in authz_groups]
        if missing:
            add(
                f"TACACS identity groups missing from tacacs_authz.csv: {missing}.",
                "tacacs_authz.csv",
            )
        for g in csv_groups:
            if g and g not in authz_groups:
                add(
                    f"User identity group '{g}' is not a TACACS identity group "
                    "from tacacs_authz.csv.",
                    "users.csv",
                    g,
                )
        per = Counter(csv_groups)
        for g in _LOCKED_GROUPS:
            if csv_rows and per.get(g) != 1:
                add(f"Need exactly one lab user in {g} (got {per.get(g)}).", "users.csv", g)

        if csv_rows:
            cols = list(csv_rows[0].keys())
            if any(c.lower() in _BANNED or "pass" in c.lower() for c in cols):
                add(
                    "users.csv must not contain a password/secret column. "
                    "Secrets stay in .env (USER_PASSWORD_DEFAULT).",
                    "users.csv",
                )
            blob = ",".join(cols).casefold() + "," + ",".join(
                str(v) for r in csv_rows for v in r.values()
            ).casefold()
            for bad in _BANNED:
                if bad in blob:
                    add(
                        f"users.csv must not contain {bad!r}. Secrets stay in env.",
                        "users.csv",
                    )
                    break

        if yaml_rows:
            yblob = yaml.safe_dump(yaml_rows).casefold() if yaml_rows else ""
            for bad in ("changeme", "cisco123", "token"):
                if bad in yblob:
                    add(f"users.yaml must not contain {bad!r}.", "users.yaml")
                    break
            # generate_nac.py also concatenates this file and refuses "password".
            yaml_text = _USERS_YAML.read_text(encoding="utf-8").casefold() if _USERS_YAML.is_file() else ""
            if "password" in yaml_text:
                add(
                    "users.yaml must not contain the word password "
                    "(secrets stay in env; nac.yaml refuses that word).",
                    "users.yaml",
                )

        users_tf = _USERS_TF.read_text(encoding="utf-8") if _USERS_TF.is_file() else ""
        vars_tf = _VARS_TF.read_text(encoding="utf-8") if _VARS_TF.is_file() else ""
        main_tf = _MAIN_TF.read_text(encoding="utf-8") if _MAIN_TF.is_file() else ""
        locals_tf = _LOCALS_TF.read_text(encoding="utf-8") if _LOCALS_TF.is_file() else ""
        versions = (_ROOT / "versions.tf").read_text(encoding="utf-8") if (_ROOT / "versions.tf").is_file() else ""

        if not _USERS_TF.is_file():
            add("users.tf is missing.", "users.tf")
        if not _USER_RES.search(users_tf):
            add(
                "users.tf must declare ise_internal_user (CiscoDevNet/ise 0.3.4). "
                "Not ise_user.",
                "users.tf",
            )
        if _WRONG_RES.search(users_tf) or _WRONG_RES.search(main_tf):
            add(
                "Do not use resource ise_user. 0.3.4 name is ise_internal_user.",
                "users.tf",
            )
        for field in (
            "name",
            "password",
            "enable_password",
            "change_password",
            "enabled",
            "first_name",
            "last_name",
            "email",
            "description",
            "identity_groups",
            "password_id_store",
            "password_never_expires",
        ):
            if field not in users_tf:
                add(
                    f"ise_internal_user must set 0.3.4 field {field}.",
                    "users.tf",
                    field,
                )
        if "ise_user_identity_group.this" not in users_tf or ".id" not in users_tf:
            add(
                "identity_groups must be comma-separated ISE identity group IDs "
                "from ise_user_identity_group.this[...].id (0.3.4).",
                "users.tf",
            )
        if "var.user_password" not in users_tf:
            add(
                "ise_internal_user.password must come from var.user_password "
                "(USER_PASSWORD_DEFAULT / TF_VAR_user_password). Not Git.",
                "users.tf",
            )
        if "user_count == 0 || length(var.user_password) > 0" not in users_tf.replace(" ", ""):
            # tolerate whitespace variants
            if not re.search(
                r"var\.user_count\s*==\s*0\s*\|\|\s*length\(\s*var\.user_password\s*\)\s*>\s*0",
                users_tf,
            ):
                add(
                    "Fail clearly when user_count>0 and the env password is empty.",
                    "users.tf",
                )
        if not _USER_DEFAULT.search(vars_tf):
            add("variable user_count default must be 8 (all lab Internal Users).", "variables.tf")
        if not _ENDPOINT_DEFAULT.search(vars_tf):
            add("Keep endpoint_count default 110.", "variables.tf")
        if not _NAD_DEFAULT.search(vars_tf):
            add("Keep nad_count default 15000.", "variables.tf")
        if "users.csv" not in locals_tf:
            add("locals.tf must csvdecode users.csv.", "locals.tf")
        if not _IDG_RES.search(main_tf):
            add("Keep ise_user_identity_group for TACACS identity groups.", "main.tf")
        if not _PROVIDER.search(versions) or not _PROVIDER_VER.search(versions):
            add("Provider stays CiscoDevNet/ise ~> 0.3.4.", "versions.tf")

        env_ex = _ENV_EXAMPLE.read_text(encoding="utf-8") if _ENV_EXAMPLE.is_file() else ""
        load_env = _LOAD_ENV.read_text(encoding="utf-8") if _LOAD_ENV.is_file() else ""
        if "USER_PASSWORD_DEFAULT=" not in env_ex:
            add(
                ".env.example must include an empty USER_PASSWORD_DEFAULT= placeholder.",
                ".env.example",
            )
        if re.search(r"^USER_PASSWORD_DEFAULT=.+$", env_ex, re.M):
            add(
                "USER_PASSWORD_DEFAULT in .env.example must be empty (no real secret).",
                ".env.example",
            )
        if "USER_ENABLE_PASSWORD_DEFAULT=" not in env_ex:
            add(
                ".env.example must include an empty USER_ENABLE_PASSWORD_DEFAULT= placeholder.",
                ".env.example",
            )
        if "TF_VAR_user_password" not in load_env or "USER_PASSWORD_DEFAULT" not in load_env:
            add(
                "load-env.ps1 must map USER_PASSWORD_DEFAULT to TF_VAR_user_password.",
                "load-env.ps1",
            )
        if "TF_VAR_user_enable_password" not in load_env:
            add(
                "load-env.ps1 must map USER_ENABLE_PASSWORD_DEFAULT to TF_VAR_user_enable_password.",
                "load-env.ps1",
            )

        data_users = data.get("users")
        if isinstance(data_users, list) and data_users:
            if len(data_users) != _USER_TOTAL:
                add(
                    f"Validated YAML users must be {_USER_TOTAL} lab Internal Users "
                    f"(got {len(data_users)}).",
                    "users",
                )

        return violations
