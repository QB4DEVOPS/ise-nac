"""FAIL if an identity group name lands in the TACACS ISE name bag.

Cisco ISE ERS shares one name namespace for TACACS command sets and
TACACS shell profiles. Identity groups are a different object type and
may keep live names (T1, auditor-internal) UNLESS a name equals a
command-set or profile ISE name (T1_cs, T1_shell, test_cs, …). Then
suffix the identity group. Do not rename live groups that do not collide.
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

_LOCKED_TACACS = frozenset(
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


def _identity_groups() -> list[tuple[str, str]]:
    """(name, path) from tacacs_authz.csv, first-seen order."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for i, row in enumerate(_tf.read_authz_csv(), start=2):
        name = (row.get("identity_group") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append((name, f"tacacs_authz.csv:identity_group:line {i}"))
    return out


def _tf_posts_csv_identity_names() -> bool:
    """True when ise_user_identity_group.name is the CSV identity group."""
    text = _tf.MAIN_TF.read_text(encoding="utf-8") if _tf.MAIN_TF.is_file() else ""
    return bool(
        "ise_user_identity_group" in text
        and "identity_groups" in text
        and "name        = each.value" in text
    )


class Rule(RuleBase):
    id = "106"
    description = (
        "FAIL if a user identity group name equals a TACACS command-set or "
        "profile ISE name (shared ERS bag). Live hyphenated names may stay."
    )
    severity = "HIGH"
    title = "IDENTITY GROUP NAMES MUST NOT COLLIDE WITH TACACS ISE NAMES"
    affected_items_label = "Identity groups"
    explanation = """\
ISE ERS uses one name namespace for TACACS command sets and TACACS
profiles. Identity groups are not that namespace. Names that already
applied (T1, T2, T3, T4, vendor, contractor, auditor-internal,
auditor-external) stay. T1 does not collide with T1_cs or T1_shell.
If an identity group string equals any command-set or profile ISE name,
suffix the identity group (for example T1_idg). Do not rename live
objects that do not collide."""
    recommendation = """\
Keep identity group and authz rule names as applied. Only suffix an
identity group when its name appears in the TACACS command-set +
profile ISE name bag (T1_cs, T1_shell, test_cs, …)."""
    references = [
        "https://github.com/netascode/nac-validate",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/user_identity_group",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        seen: set[tuple[str, str]] = set()

        def add(v: Violation) -> None:
            key = (str(v.details.get("name", "")), str(v.details.get("source", "")))
            if key in seen:
                return
            seen.add(key)
            violations.append(v)

        tacacs_names: set[str] = set()
        for name, _path in _tf.posted_names("command_set"):
            tacacs_names.add(name)
        for name, _path in _tf.posted_names("shell_profile"):
            tacacs_names.add(name)
        for name, _path in _tf.literal_resource_names("ise_tacacs_command_set"):
            tacacs_names.add(name)
        for name, _path in _tf.literal_resource_names("ise_tacacs_profile"):
            tacacs_names.add(name)
        tacacs_names |= _LOCKED_TACACS

        groups = _identity_groups()
        yaml_groups: list[tuple[str, str]] = []
        for row in data.get("tacacs_authz") or []:
            if not isinstance(row, dict):
                continue
            name = row.get("identity_group")
            if isinstance(name, str) and name:
                yaml_groups.append(
                    (name, f"tacacs_authz[name={row.get('name', 'unnamed')}].identity_group")
                )

        for name, path in groups + yaml_groups:
            if name not in tacacs_names:
                continue
            add(
                Violation(
                    message=(
                        f"Identity group '{name}' equals a TACACS command-set or "
                        "profile ISE name. ISE ERS shares that namespace. Suffix "
                        "the identity group (for example "
                        f"{name}_idg); do not reuse '{name}'."
                    ),
                    path=path,
                    details={
                        "name": name,
                        "kind": "identity_group_collision",
                        "source": path,
                    },
                )
            )

        if groups and not _tf_posts_csv_identity_names():
            add(
                Violation(
                    message=(
                        "ise_user_identity_group must POST the CSV identity "
                        "group name (name = each.value). Do not map those "
                        "names through the TACACS _cs/_shell suffix unless "
                        "they collide with that bag."
                    ),
                    path="main.tf:ise_user_identity_group.this",
                    details={
                        "name": "*",
                        "kind": "identity_group_wiring",
                        "source": "terraform",
                    },
                )
            )

        return violations
