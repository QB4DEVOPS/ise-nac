"""FAIL if a TACACS command-set ISE name equals a TACACS profile ISE name.

Cisco ISE ERS uses ONE shared name namespace for TACACS command sets and
TACACS shell profiles. The ISE POST names are a locked list (underscore
only). CSV/YAML tier keys may stay T1. Identity groups, NDGs, and authz
rule names are not this namespace and are not renamed here.
"""

from __future__ import annotations

import importlib.util
import re
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

# Locked ISE POST names. Underscore only. No two strings in the union match.
_LOCKED_COMMAND_SETS = frozenset(
    {
        "T1",
        "T2",
        "T3",
        "T4",
        "vendor",
        "contractor",
        "auditor_internal",
        "auditor_external",
        "test",
    }
)
_LOCKED_PROFILES = frozenset(
    {
        "T1_shell",
        "T2_shell",
        "T3_shell",
        "T4_shell",
        "vendor_shell",
        "contractor_shell",
        "auditor_internal_shell",
        "auditor_external_shell",
    }
)
_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _collect_command_set_ise_names(data: dict[str, Any]) -> list[tuple[str, str]]:
    """ISE names for command sets: Terraform POSTs, YAML, nac.yaml, test canary."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(name: str, path: str) -> None:
        if not name or name in seen:
            return
        seen.add(name)
        out.append((name, path))

    for name, path in _tf.posted_names("command_set"):
        add(name, path)
    for name, path in _tf.literal_resource_names("ise_tacacs_command_set"):
        add(name, path)
    for name in _tf.command_set_defs():
        add(name, f"command_sets.yaml[name={name}].name")
    for item in data.get("command_sets") or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            add(item["name"], f"command_sets[name={item['name']}].name")
    return out


def _collect_profile_ise_names(data: dict[str, Any]) -> list[tuple[str, str]]:
    """ISE names for profiles: Terraform POSTs, YAML, nac.yaml."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(name: str, path: str) -> None:
        if not name or name in seen:
            return
        seen.add(name)
        out.append((name, path))

    for rec in _tf.posted_records("shell_profile"):
        add(rec["ise_name"], rec["path"])
    for name, path in _tf.literal_resource_names("ise_tacacs_profile"):
        add(name, path)
    for name in _tf.shell_profile_defs():
        add(name, f"shell_profiles.yaml[name={name}].name")
    for item in data.get("shell_profiles") or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            add(item["name"], f"shell_profiles[name={item['name']}].name")
    return out


class Rule(RuleBase):
    id = "105"
    description = (
        "FAIL if a TACACS command-set ISE name equals a TACACS profile ISE name; "
        "ISE POST names must match the locked unique list (underscore only)"
    )
    severity = "HIGH"
    title = "TACACS COMMAND SET AND PROFILE ISE NAMES MUST BE UNIQUE"
    affected_items_label = "ISE names"
    explanation = """\
Cisco ISE ERS uses one shared name namespace for TACACS command sets and
TACACS shell profiles. No two ISE names on this locked list may match.
Command-set ISE names: T1 T2 T3 T4 vendor contractor auditor_internal
auditor_external test.
Profile ISE names: T1_shell T2_shell T3_shell T4_shell vendor_shell
contractor_shell auditor_internal_shell auditor_external_shell.
Underscore only (no hyphens). CSV keys stay T1. YAML profile name: values
are the ISE names (T1_shell). Identity groups, NDGs, and authz rule names
are unchanged and are not this check."""
    recommendation = """\
POST exactly the locked lists. Keep command-set ISE names unsuffixed.
shell_profiles.yaml name: must be T1_shell (not T1). Keep CSV keys as T1.
Wire ise_tacacs_profile.this name to local.ise_tacacs_shell_profile_name.
Do not rename identity groups, NDGs, or authz rule names for this."""
    references = [
        "https://github.com/netascode/nac-validate",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/tacacs_profile",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/tacacs_command_set",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        seen: set[tuple[str, str, str]] = set()

        def add(v: Violation) -> None:
            key = (
                str(v.details.get("name", "")),
                str(v.details.get("kind", "")),
                str(v.details.get("source", "")),
            )
            if key in seen:
                return
            seen.add(key)
            violations.append(v)

        # The locked lists themselves must not overlap.
        locked_overlap = sorted(_LOCKED_COMMAND_SETS & _LOCKED_PROFILES)
        for name in locked_overlap:
            add(
                Violation(
                    message=(
                        f"Locked ISE name '{name}' is on both the command-set "
                        "list and the profile list. Those lists must be unique."
                    ),
                    path=".rules/tacacs_shared_namespace.py",
                    details={
                        "name": name,
                        "kind": "locked_collision",
                        "source": "lock",
                    },
                )
            )

        command_sets = _collect_command_set_ise_names(data)
        profiles = _collect_profile_ise_names(data)
        command_set_names = {name: path for name, path in command_sets}
        profile_names = {name: path for name, path in profiles}

        def check_charset(kind: str, name: str, path: str) -> None:
            if _NAME_RE.fullmatch(name):
                return
            add(
                Violation(
                    message=(
                        f"TACACS {kind} ISE name '{name}' is not underscore-only. "
                        "ISE POST names may use letters, digits, and underscore "
                        "(no hyphens)."
                    ),
                    path=path,
                    details={"name": name, "kind": kind, "source": "charset"},
                )
            )

        for name, path in command_sets:
            check_charset("command-set", name, path)
        for name, path in profiles:
            check_charset("profile", name, path)

        posted_cs = set(command_set_names)
        posted_pr = set(profile_names)

        extra_cs = sorted(posted_cs - _LOCKED_COMMAND_SETS)
        missing_cs = sorted(_LOCKED_COMMAND_SETS - posted_cs)
        extra_pr = sorted(posted_pr - _LOCKED_PROFILES)
        missing_pr = sorted(_LOCKED_PROFILES - posted_pr)

        for name in extra_cs:
            add(
                Violation(
                    message=(
                        f"TACACS command-set ISE name '{name}' is not on the "
                        "locked list (T1 T2 T3 T4 vendor contractor "
                        "auditor_internal auditor_external test)."
                    ),
                    path=command_set_names[name],
                    details={
                        "name": name,
                        "kind": "command_set_lock",
                        "source": "terraform",
                    },
                )
            )
        for name in missing_cs:
            add(
                Violation(
                    message=(
                        f"Locked command-set ISE name '{name}' is not POSTed. "
                        "The locked list must be posted in full."
                    ),
                    path="main.tf:ise_tacacs_command_set",
                    details={
                        "name": name,
                        "kind": "command_set_lock",
                        "source": "terraform",
                    },
                )
            )
        for name in extra_pr:
            add(
                Violation(
                    message=(
                        f"TACACS profile ISE name '{name}' is not on the locked "
                        "list (T1_shell T2_shell T3_shell T4_shell vendor_shell "
                        "contractor_shell auditor_internal_shell "
                        "auditor_external_shell)."
                    ),
                    path=profile_names[name],
                    details={
                        "name": name,
                        "kind": "profile_lock",
                        "source": "terraform",
                    },
                )
            )
        for name in missing_pr:
            add(
                Violation(
                    message=(
                        f"Locked profile ISE name '{name}' is not POSTed. "
                        "The locked list must be posted in full."
                    ),
                    path="main.tf:ise_tacacs_profile",
                    details={
                        "name": name,
                        "kind": "profile_lock",
                        "source": "terraform",
                    },
                )
            )

        # MUST fail if a command-set ISE name equals a profile ISE name.
        for name in sorted(posted_cs & posted_pr):
            add(
                Violation(
                    message=(
                        f"TACACS command-set ISE name '{name}' equals profile "
                        f"ISE name '{name}'. ISE ERS shares one namespace; "
                        "this 400s on apply. Command sets stay T1; profiles "
                        "are T1_shell. No two locked ISE names may match."
                    ),
                    path=profile_names[name],
                    details={
                        "name": name,
                        "kind": "collision",
                        "command_set_path": command_set_names[name],
                        "source": "terraform",
                    },
                )
            )

        if not re.search(
            r"profile\s*=\s*ise_tacacs_profile\.this\[each\.value\.shell_profile\]\.name",
            _tf.MAIN_TF.read_text(encoding="utf-8") if _tf.MAIN_TF.is_file() else "",
        ):
            add(
                Violation(
                    message=(
                        "Authorization rules must set profile = "
                        "ise_tacacs_profile.this[each.value.shell_profile].name "
                        "so they POST the suffixed ISE name (T1_shell), not the "
                        "CSV tier key (T1)."
                    ),
                    path="main.tf:ise_device_admin_authorization_rule.authz",
                    details={
                        "name": "profile",
                        "kind": "authz",
                        "source": "terraform",
                    },
                )
            )

        if not posted_cs or not posted_pr:
            add(
                Violation(
                    message=(
                        "Cannot prove command-set ISE names differ from profile "
                        "ISE names (one side POSTs nothing). Fail closed."
                    ),
                    path="main.tf",
                    details={
                        "name": "*",
                        "kind": "fail_closed",
                        "source": "terraform",
                    },
                )
            )

        return violations
