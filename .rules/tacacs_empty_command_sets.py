"""Empty TACACS command sets must permit unmatched traffic."""

from __future__ import annotations

from typing import Any

from nac_validate import RuleBase, Violation


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


class Rule(RuleBase):
    id = "102"
    description = (
        "TACACS command sets with no commands must set permit_unmatched: true"
    )
    severity = "HIGH"
    title = "EMPTY TACACS COMMAND SET"
    affected_items_label = "Empty command sets"
    explanation = """\
ISE rejects TACACS command sets that have no commands when permit_unmatched is
false. This repo's CSVs only have command-set names (no IOS commands). Empty
sets must set permit_unmatched: true or ISE returns HTTP 400 on apply."""
    recommendation = """\
Either add commands under command_sets[].commands, or set
permit_unmatched: true on every command set that has an empty command list.
A name listed only in tacacs_authz.command_set with no command_sets entry
is treated as empty with permit_unmatched false."""
    references = [
        "https://github.com/netascode/nac-validate",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            return []

        defined: dict[str, dict[str, Any]] = {}
        for item in data.get("command_sets") or []:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                defined[item["name"]] = item

        names: set[str] = set(defined)
        authz_paths: dict[str, str] = {}
        for row in data.get("tacacs_authz") or []:
            if not isinstance(row, dict):
                continue
            name = row.get("command_set")
            if isinstance(name, str) and name:
                names.add(name)
                authz_paths.setdefault(
                    name,
                    f"tacacs_authz[name={row.get('name', 'unnamed')}].command_set",
                )

        violations: list[Violation] = []
        for name in sorted(names):
            entry = defined.get(name)
            if _has_commands(entry):
                continue
            if _permits_unmatched(entry):
                continue
            if entry is not None:
                path = f"command_sets[name={name}]"
            else:
                path = authz_paths.get(name, f"command_sets[name={name}]")
            violations.append(
                Violation(
                    message=(
                        f"TACACS command set '{name}' has no commands and "
                        "permit_unmatched is false. ISE rejects empty command "
                        "sets unless they permit unmatched. Add commands, or set "
                        "permit_unmatched: true, before terraform apply."
                    ),
                    path=path,
                    details={
                        "command_set": name,
                        "commands": 0,
                        "permit_unmatched": False,
                    },
                )
            )
        return violations
