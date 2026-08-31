"""Empty TACACS command sets must permit unmatched traffic.

Checks permit_unmatched on the Terraform resource ISE receives, not only nac.yaml.
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
        "Empty TACACS command sets Terraform POSTs must set permit_unmatched = true"
    )
    severity = "HIGH"
    title = "EMPTY TACACS COMMAND SET"
    affected_items_label = "Empty command sets"
    explanation = """\
ISE rejects TACACS command sets that have no commands when permit_unmatched is
false. Terraform POSTs ise_tacacs_command_set from tacacs_authz.csv names with
no IOS commands. If that resource sets permit_unmatched = false (or omits it),
apply returns HTTP 400. nac.yaml can drift; this rule reads main.tf."""
    recommendation = """\
Set permit_unmatched = true on resource.ise_tacacs_command_set when commands
are empty, and set permit_unmatched: true on YAML command_sets with no commands."""
    references = [
        "https://github.com/netascode/nac-validate",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        posted = _tf.posted_names("command_set")
        resource = _tf.command_set_resource()
        tf_permit = resource["permit_unmatched"]
        tf_has_commands = bool(resource["has_commands"])

        # What apply POSTs: empty command-set resource + permit_unmatched false.
        if posted and not tf_has_commands and tf_permit is not True:
            for name, _csv_path in posted:
                violations.append(
                    Violation(
                        message=(
                            f"TACACS command set '{name}' is POSTed empty with "
                            "permit_unmatched = false (or unset) in Terraform. "
                            "ISE rejects empty command sets unless they permit "
                            "unmatched. Set permit_unmatched = true in main.tf."
                        ),
                        path=resource["path"],
                        details={
                            "command_set": name,
                            "commands": 0,
                            "permit_unmatched": False if tf_permit is not True else True,
                            "source": "terraform",
                        },
                    )
                )

        defined: dict[str, dict[str, Any]] = {}
        for item in data.get("command_sets") or []:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                defined[item["name"]] = item

        yaml_failed: set[str] = {str(v.details.get("command_set", "")) for v in violations}
        for name, entry in sorted(defined.items()):
            if name in yaml_failed:
                continue
            if _has_commands(entry):
                continue
            if _permits_unmatched(entry):
                continue
            violations.append(
                Violation(
                    message=(
                        f"TACACS command set '{name}' has no commands and "
                        "permit_unmatched is false. ISE rejects empty command "
                        "sets unless they permit unmatched."
                    ),
                    path=f"command_sets[name={name}]",
                    details={
                        "command_set": name,
                        "commands": 0,
                        "permit_unmatched": False,
                    },
                )
            )
        return violations
