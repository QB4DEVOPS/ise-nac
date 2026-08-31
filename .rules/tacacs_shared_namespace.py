"""FAIL if a TACACS command-set ISE name equals a TACACS profile ISE name.

Cisco ISE ERS uses ONE shared name namespace for TACACS command sets and
TACACS shell profiles. Creating both named T1 (or T2, vendor, contractor, …)
returns HTTP 400. CSV/YAML tier keys may stay T1; profile ISE names must be
T1_shell (no hyphens). The GUI canary command set named test must not have
a matching profile.
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

_SHELL_SUFFIX = "_shell"


def _collect_command_set_ise_names() -> list[tuple[str, str]]:
    """ISE names Terraform POSTs for command sets, including the test canary."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for name, path in _tf.posted_names("command_set"):
        if name in seen:
            continue
        seen.add(name)
        out.append((name, path))
    for name, path in _tf.literal_resource_names("ise_tacacs_command_set"):
        if name in seen:
            continue
        seen.add(name)
        out.append((name, path))
    return out


class Rule(RuleBase):
    id = "105"
    description = (
        "FAIL if a TACACS command-set ISE name equals a TACACS profile ISE name "
        "(ERS shared namespace); profile ISE names must be {tier}_shell"
    )
    severity = "HIGH"
    title = "TACACS COMMAND SET AND PROFILE ISE NAMES MUST NOT COLLIDE"
    affected_items_label = "Colliding ISE names"
    explanation = """\
Cisco ISE ERS uses one shared name namespace for TACACS command sets and
TACACS shell profiles. You cannot create both named T1 (or T2, vendor,
contractor, auditor_internal, auditor_external). A profile create while the
matching command set exists returns HTTP 400; the reverse also 400s.
CSV/YAML tier keys may stay T1. Profile ISE names Terraform POSTs must be
T1_shell, T2_shell, T3_shell, T4_shell, vendor_shell, contractor_shell,
auditor_internal_shell, auditor_external_shell (underscore, no hyphens).
Command-set ISE names stay T1, T2, T3, T4, vendor, contractor,
auditor_internal, auditor_external, and the GUI canary test.
Authz rules must use ise_tacacs_profile.this[...].name so they pick up
the suffix. Do not name a profile test."""
    recommendation = """\
Set local.ise_tacacs_shell_profile_name to {hyphen-mapped CSV key}_shell.
Wire resource.ise_tacacs_profile.this name to that map. Keep command-set
ISE names unsuffixed. Keep CSV/YAML keys as T1 etc. Point authorization
profile at ise_tacacs_profile.this[each.value.shell_profile].name.
depends_on the command-set resources so creates cannot race."""
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

        command_sets = _collect_command_set_ise_names()
        command_set_names = {name: path for name, path in command_sets}
        profile_records = _tf.posted_records("shell_profile")

        for rec in profile_records:
            csv_key = rec.get("csv_key") or ""
            ise_name = rec["ise_name"]
            path = rec["path"]
            expected = (
                f"{csv_key.replace('-', '_')}{_SHELL_SUFFIX}" if csv_key else ""
            )
            if expected and ise_name != expected:
                add(
                    Violation(
                        message=(
                            f"TACACS profile CSV key '{csv_key}' POSTs ISE name "
                            f"'{ise_name}' but must POST '{expected}'. ISE ERS "
                            "shares one name namespace with command sets; "
                            "profile names get a _shell suffix (no hyphens)."
                        ),
                        path=path,
                        details={
                            "name": ise_name,
                            "expected": expected,
                            "kind": "shell_profile",
                            "source": "terraform",
                        },
                    )
                )

        for rec in profile_records:
            ise_name = rec["ise_name"]
            if ise_name not in command_set_names:
                continue
            add(
                Violation(
                    message=(
                        f"TACACS profile ISE name '{ise_name}' equals command-set "
                        f"ISE name '{ise_name}'. ISE ERS shares one namespace; "
                        "this 400s on apply. Use {tier}_shell for profiles "
                        "(T1_shell, vendor_shell, …). Command sets keep T1."
                    ),
                    path=rec["path"],
                    details={
                        "name": ise_name,
                        "kind": "collision",
                        "command_set_path": command_set_names[ise_name],
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
        if command_sets and not profile_records:
            add(
                Violation(
                    message=(
                        "Terraform POSTs TACACS command sets but no shell "
                        "profiles. Cannot prove profile ISE names differ from "
                        "command-set ISE names. Fail closed."
                    ),
                    path="main.tf:ise_tacacs_profile",
                    details={
                        "name": "*",
                        "kind": "fail_closed",
                        "source": "terraform",
                    },
                )
            )

        return violations
