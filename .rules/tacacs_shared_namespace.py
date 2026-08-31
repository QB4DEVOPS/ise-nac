"""FAIL on any duplicate in the combined TACACS ISE name set.

Cisco ISE ERS uses ONE shared name namespace for TACACS command sets and
TACACS shell profiles. Every command-set ISE name and every profile ISE
name is one bag of strings. Any string that appears more than once in
that bag FAILS. Every TACACS object is suffixed (_cs or _shell). CSV keys
stay T1. Identity groups, NDGs, and authz rule names are not this namespace.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections import Counter
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
        "T1_cs",
        "T2_cs",
        "T3_cs",
        "T4_cs",
        "vendor_cs",
        "contractor_cs",
        "auditor_internal_cs",
        "auditor_external_cs",
        "test_cs",
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


def _item_names(items: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
            out.append(item["name"])
    return out


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
        "FAIL on any duplicate in the combined set of all TACACS command-set "
        "ISE names and all TACACS profile ISE names (one ERS namespace)"
    )
    severity = "HIGH"
    title = "TACACS COMMAND SET AND PROFILE ISE NAMES MUST BE UNIQUE"
    affected_items_label = "ISE names"
    explanation = """\
Cisco ISE ERS uses one shared name namespace for TACACS command sets and
TACACS shell profiles. All command-set ISE names and all profile ISE
names are ONE set. Any duplicate string in that combined set FAILS.
Locked names (underscore only; every TACACS object is suffixed):
Command sets: T1_cs T2_cs T3_cs T4_cs vendor_cs contractor_cs
auditor_internal_cs auditor_external_cs test_cs.
Profiles: T1_shell T2_shell T3_shell T4_shell vendor_shell
contractor_shell auditor_internal_shell auditor_external_shell.
No profile named test_cs. CSV keys stay T1. YAML name: values are the
ISE names. Identity groups, NDGs, and authz rule names are not this check."""
    recommendation = """\
Every ISE name in command_sets.yaml, shell_profiles.yaml, and Terraform
POSTs must be unique across BOTH object types. Command sets are T1_cs.
Profiles are T1_shell. Canary ise_tacacs_command_set.test POSTs test_cs.
Keep CSV keys as T1."""
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

        def fail_list_duplicates(
            names: list[str], path: str, kind: str, source: str
        ) -> None:
            for name, count in sorted(Counter(names).items()):
                if count < 2 or not name:
                    continue
                add(
                    Violation(
                        message=(
                            f"TACACS {kind} ISE name '{name}' appears {count} "
                            f"times in {path}. Combined command-set + profile "
                            "names must be unique."
                        ),
                        path=path,
                        details={
                            "name": name,
                            "kind": "combined_duplicate",
                            "count": count,
                            "source": source,
                        },
                    )
                )

        yaml_cs = _item_names(
            _tf._load_yaml_list(_tf.COMMAND_SETS_YAML, "command_sets")
        )
        fail_list_duplicates(
            yaml_cs,
            "command_sets.yaml",
            "command-set",
            "command_sets.yaml",
        )
        for name in yaml_cs:
            if name.endswith("_cs"):
                continue
            add(
                Violation(
                    message=(
                        f"command_sets.yaml name: '{name}' must be the ISE POST "
                        "name with a _cs suffix (T1_cs, vendor_cs, …). CSV keys "
                        "stay T1."
                    ),
                    path=f"command_sets.yaml[name={name}].name",
                    details={
                        "name": name,
                        "kind": "command_set_lock",
                        "source": "command_sets.yaml",
                    },
                )
            )
        fail_list_duplicates(
            _item_names(
                _tf._load_yaml_list(_tf.SHELL_PROFILES_YAML, "shell_profiles")
            ),
            "shell_profiles.yaml",
            "profile",
            "shell_profiles.yaml",
        )
        fail_list_duplicates(
            _item_names(data.get("command_sets")),
            "command_sets",
            "command-set",
            "nac.yaml",
        )
        fail_list_duplicates(
            _item_names(data.get("shell_profiles")),
            "shell_profiles",
            "profile",
            "nac.yaml",
        )

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
                        "locked list (T1_cs T2_cs T3_cs T4_cs vendor_cs "
                        "contractor_cs auditor_internal_cs auditor_external_cs "
                        "test_cs)."
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

        # ONE set: every command-set ISE name and every profile ISE name.
        # Fail on any duplicate string in that bag.
        combined_paths: dict[str, list[str]] = {}
        for name, path in command_sets:
            combined_paths.setdefault(name, []).append(path)
        for name, path in profiles:
            combined_paths.setdefault(name, []).append(path)
        for name in sorted(combined_paths):
            paths = combined_paths[name]
            if len(paths) < 2:
                continue
            add(
                Violation(
                    message=(
                        f"TACACS ISE name '{name}' is duplicated {len(paths)} "
                        "times in the combined command-set + profile name set. "
                        "ISE ERS shares one namespace; any duplicate 400s on "
                        "apply. All command-set names and all profile names "
                        "must be unique together."
                    ),
                    path=paths[-1],
                    details={
                        "name": name,
                        "kind": "combined_duplicate",
                        "count": len(paths),
                        "paths": paths,
                        "source": "combined",
                    },
                )
            )

        if "test_cs" in profile_names:
            add(
                Violation(
                    message=(
                        "TACACS profile ISE name 'test_cs' collides with the GUI "
                        "canary command set named test_cs. Do not create a "
                        "profile named test_cs."
                    ),
                    path=profile_names["test_cs"],
                    details={
                        "name": "test_cs",
                        "kind": "combined_duplicate",
                        "source": "canary",
                    },
                )
            )

        tf_text = _tf.MAIN_TF.read_text(encoding="utf-8") if _tf.MAIN_TF.is_file() else ""
        if not re.search(
            r"command_sets\s*=\s*\[ise_tacacs_command_set\.this\[each\.value\.command_set\]\.name\]",
            tf_text,
        ):
            add(
                Violation(
                    message=(
                        "Authorization rules must set command_sets = "
                        "[ise_tacacs_command_set.this[each.value.command_set].name] "
                        "so they POST the suffixed ISE name (T1_cs), not the "
                        "CSV tier key (T1)."
                    ),
                    path="main.tf:ise_device_admin_authorization_rule.authz",
                    details={
                        "name": "command_sets",
                        "kind": "authz",
                        "source": "terraform",
                    },
                )
            )
        if not re.search(
            r"profile\s*=\s*ise_tacacs_profile\.this\[each\.value\.shell_profile\]\.name",
            tf_text,
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
