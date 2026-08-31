"""ISE TACACS command-set and shell-profile names cannot contain hyphens."""

from __future__ import annotations

import re
from typing import Any

from nac_validate import RuleBase, Violation

# ISE TACACS profile names: alphanumeric, underscore, space. No hyphens.
_NAME_RE = re.compile(r"^[A-Za-z0-9_ ]+$")


class Rule(RuleBase):
    id = "101"
    description = (
        "TACACS command_set and shell_profile names may only use "
        "[A-Za-z0-9_ ] (no hyphens)"
    )
    severity = "HIGH"
    title = "INVALID TACACS PROFILE NAME"
    affected_items_label = "Invalid names"
    explanation = """\
Cisco ISE TACACS command-set and shell-profile names cannot contain hyphens.
Only letters, digits, underscore, and space are allowed. Names such as
auditor-internal and auditor-external cause HTTP 400 on terraform apply."""
    recommendation = """\
Rename command_set and shell_profile values to use underscore instead of hyphen.
Example: auditor-internal -> auditor_internal, auditor-external -> auditor_external.
Authorization rule names and identity groups are not this ISE constraint."""
    references = [
        "https://github.com/netascode/nac-validate",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            return []

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
            violations.append(
                Violation(
                    message=(
                        f"TACACS {kind} name '{name}' is invalid. "
                        "ISE allows only letters, digits, underscore, and space "
                        "(no hyphens). Rename before terraform apply."
                    ),
                    path=path,
                    details={"kind": kind, "name": name},
                )
            )

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
