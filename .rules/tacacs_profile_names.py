"""ISE TACACS command-set and shell-profile names cannot contain hyphens.

Checks the names Terraform POSTs (CSV columns locals.tf uses for
ise_tacacs_command_set / ise_tacacs_profile), not only nac.yaml.
NDG names (access-marketing, …) and identity groups are not this rule.
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

# ISE TACACS command-set and profile names: alphanumeric, underscore, space.
_NAME_RE = re.compile(r"^[A-Za-z0-9_ ]+$")


class Rule(RuleBase):
    id = "101"
    description = (
        "TACACS command-set and profile names Terraform POSTs to ISE may only "
        "use [A-Za-z0-9_ ] (no hyphens)"
    )
    severity = "HIGH"
    title = "INVALID TACACS PROFILE NAME"
    affected_items_label = "Invalid names"
    explanation = """\
Cisco ISE TACACS command-set and TACACS profile (shell profile) names cannot
contain hyphens. Only letters, digits, underscore, and space are allowed.
Terraform POSTs those names from tacacs_authz.csv via locals.tf
(command_sets / shell_profiles), not from nac.yaml. Hyphenated names such as
auditor-internal and auditor-external return HTTP 400 on apply.
NDG names (access-marketing) are allowed to keep hyphens."""
    recommendation = """\
Rename the command_set and shell_profile columns Terraform POSTs (underscores,
not hyphens). Example: auditor-internal -> auditor_internal.
Do not rename NDG rows or identity groups for this ISE constraint."""
    references = [
        "https://github.com/netascode/nac-validate",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        seen: set[tuple[str, str]] = set()

        def check(kind: str, name: Any, path: str) -> None:
            if not isinstance(name, str) or name == "":
                return
            if _NAME_RE.fullmatch(name):
                return
            key = (kind, name)
            if key in seen:
                return
            seen.add(key)
            label = "command-set" if kind == "command_set" else "profile"
            violations.append(
                Violation(
                    message=(
                        f"TACACS {label} name '{name}' is invalid. "
                        "ISE allows only letters, digits, underscore, and space "
                        "(no hyphens). This is a name Terraform POSTs to ISE."
                    ),
                    path=path,
                    details={"kind": kind, "name": name},
                )
            )

        # What apply actually sends (CSV + locals.tf mapping).
        for name, path in _tf.posted_names("command_set"):
            check("command_set", name, path)
        for name, path in _tf.posted_names("shell_profile"):
            check("shell_profile", name, path)

        # YAML still checked so nac.yaml cannot silently drift into hyphens.
        for row in data.get("tacacs_authz") or []:
            if not isinstance(row, dict):
                continue
            row_name = row.get("name", "unnamed")
            check(
                "command_set",
                row.get("command_set"),
                f"tacacs_authz[name={row_name}].command_set",
            )
            check(
                "shell_profile",
                row.get("shell_profile"),
                f"tacacs_authz[name={row_name}].shell_profile",
            )

        for item in data.get("command_sets") or []:
            if isinstance(item, dict):
                name = item.get("name")
                check("command_set", name, f"command_sets[name={name}].name")

        for item in data.get("shell_profiles") or []:
            if isinstance(item, dict):
                name = item.get("name")
                check("shell_profile", name, f"shell_profiles[name={name}].name")

        return violations
