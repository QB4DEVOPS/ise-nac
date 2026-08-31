"""TACACS command sets must contain IOS commands except T4.

T4 may be empty with permit_unmatched=true (full device-admin).
Every other set must have at least one command and permit_unmatched=false.
Empty + permit_unmatched=false is invalid on ISE (HTTP 400).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from nac_validate import RuleBase, Violation

_ROOT = Path(__file__).resolve().parents[1]
_HELPER = _ROOT / "scripts" / "tf_ise_post.py"
_spec = importlib.util.spec_from_file_location("tf_ise_post", _HELPER)
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {_HELPER}")
_tf = importlib.util.module_from_spec(_spec)
sys.modules["tf_ise_post"] = _tf
_spec.loader.exec_module(_tf)

_T4 = frozenset({"T4", "T4_cs"})


def _has_commands(entry: dict[str, Any] | None) -> bool:
    if not entry:
        return False
    commands = entry.get("commands")
    return isinstance(commands, list) and len(commands) > 0


def _permits_unmatched(entry: dict[str, Any] | None) -> bool:
    if not entry:
        return False
    value = entry.get("permit_unmatched")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"true", "yes", "1"}
    return False


def _check_entry(
    name: str,
    entry: dict[str, Any] | None,
    path: str,
    source: str,
) -> Violation | None:
    has = _has_commands(entry)
    permit = _permits_unmatched(entry)
    if name in _T4:
        if not permit:
            return Violation(
                message=(
                    f"TACACS command set '{name}' must set permit_unmatched = true "
                    f"({source}). T4 is full device-admin."
                ),
                path=path,
                details={
                    "command_set": name,
                    "commands": len(entry.get("commands") or []) if entry else 0,
                    "permit_unmatched": permit,
                    "source": source,
                },
            )
        return None
    if permit:
        return Violation(
            message=(
                f"TACACS command set '{name}' must set permit_unmatched = false "
                f"({source}). Only T4 may permit unmatched."
            ),
            path=path,
            details={
                "command_set": name,
                "commands": len(entry.get("commands") or []) if entry else 0,
                "permit_unmatched": True,
                "source": source,
            },
        )
    if not has:
        return Violation(
            message=(
                f"TACACS command set '{name}' has no IOS commands ({source}). "
                "ISE rejects empty command sets unless they permit unmatched. "
                "Non-T4 sets must list real commands with permit_unmatched = false."
            ),
            path=path,
            details={
                "command_set": name,
                "commands": 0,
                "permit_unmatched": False,
                "source": source,
            },
        )
    return None


class Rule(RuleBase):
    id = "102"
    description = (
        "TACACS command sets must include IOS commands except T4, which may "
        "be empty with permit_unmatched = true"
    )
    severity = "HIGH"
    title = "TACACS COMMAND SET COMMANDS"
    affected_items_label = "Command sets"
    explanation = """\
ISE rejects TACACS command sets that have no commands when permit_unmatched is
false (HTTP 400). Non-T4 sets (T1–T3, vendor, contractor, auditor_*) must
contain real IOS commands and deny unmatched. T4 is full device-admin and may
be empty with permit_unmatched = true. Terraform yamldecodes command_sets.yaml;
nac.yaml can drift, so this rule reads both plus main.tf."""
    recommendation = """\
Put IOS commands in command_sets.yaml (grant PERMIT, command, arguments).
Set permit_unmatched: false except T4 (permit_unmatched: true). Rebuild
nac.yaml with python3 scripts/generate_nac.py. Wire the YAML into
resource.ise_tacacs_command_set commands in main.tf."""
    references = [
        "https://github.com/netascode/nac-validate",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/latest/docs/resources/tacacs_command_set",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        seen: set[tuple[str, str]] = set()

        def add(v: Violation | None) -> None:
            if v is None:
                return
            key = (str(v.details.get("command_set", "")), str(v.details.get("source", "")))
            if key in seen:
                return
            seen.add(key)
            violations.append(v)

        posted = _tf.posted_names("command_set")
        resource = _tf.command_set_resource()
        file_defs = _tf.command_set_defs()

        yaml_defs: dict[str, dict[str, Any]] = {}
        for item in data.get("command_sets") or []:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                yaml_defs[item["name"]] = item

        non_t4 = [name for name, _ in posted if name not in _T4]
        if non_t4 and not resource["has_commands"]:
            for name, _csv_path in posted:
                if name in _T4:
                    continue
                add(
                    Violation(
                        message=(
                            f"TACACS command set '{name}' is POSTed without a "
                            "commands block in Terraform. Non-T4 sets need real "
                            "IOS commands (grant PERMIT, command, arguments)."
                        ),
                        path=resource["path"],
                        details={
                            "command_set": name,
                            "commands": 0,
                            "permit_unmatched": resource["permit_unmatched"],
                            "source": "terraform",
                        },
                    )
                )

        if resource["permit_unmatched"] is True and non_t4:
            for name, _csv_path in posted:
                if name in _T4:
                    continue
                add(
                    Violation(
                        message=(
                            f"TACACS command set '{name}' is POSTed with "
                            "permit_unmatched = true in Terraform. Only T4 may "
                            "permit unmatched."
                        ),
                        path=resource["path"],
                        details={
                            "command_set": name,
                            "permit_unmatched": True,
                            "source": "terraform",
                        },
                    )
                )

        for rec in _tf.posted_records("command_set"):
            name = rec["ise_name"]
            csv_path = rec["path"]
            keys = _tf.yaml_lookup_keys("command_set", name, rec.get("csv_key"))
            entry = None
            for key in keys:
                if key in file_defs:
                    entry = file_defs[key]
                    break
            if entry is None:
                add(
                    Violation(
                        message=(
                            f"TACACS command set '{name}' is POSTed from "
                            "tacacs_authz.csv but missing from command_sets.yaml."
                        ),
                        path=csv_path,
                        details={
                            "command_set": name,
                            "commands": 0,
                            "source": "command_sets.yaml",
                        },
                    )
                )
                continue
            add(_check_entry(name, entry, "command_sets.yaml", "command_sets.yaml"))

        for name, entry in sorted(yaml_defs.items()):
            add(_check_entry(name, entry, f"command_sets[name={name}]", "nac.yaml"))

        return violations
