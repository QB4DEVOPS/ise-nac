"""ISE ERS TACACS command-set arguments must be literal tokens, not PCRE.

command = first IOS word only. arguments = remaining words. * is the ISE
wildcard. Parentheses, ?, .*, and other regex metacharacters 400 on apply
("generic Application resource validation exception"). nac-validate exit 0
must mean the payload is ISE-legal, not only schema-shaped.
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

# First-word commands ISE ERS accepts for this access-switch ladder.
_ALLOWED_COMMANDS = frozenset(
    {
        "show",
        "ping",
        "traceroute",
        "configure",
        "config",
        "interface",
        "description",
        "shutdown",
        "vlan",
        "spanning-tree",
        "copy",
        "end",
        "exit",
        "switchport",
        "no",
    }
)

# Literal argument tokens, spaces, hyphen, and * wildcard. No regex.
_ARGS_RE = re.compile(r"^[A-Za-z0-9_ *\-]*$")
_COMMAND_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REGEX_HINT = re.compile(r"[()[\]{}|^$?+.]|\\")


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _check_command(
    set_name: str,
    index: int,
    cmd: dict[str, Any],
    path: str,
    source: str,
) -> Violation | None:
    grant = _as_str(cmd.get("grant")).upper()
    command = _as_str(cmd.get("command")).strip()
    arguments = _as_str(cmd.get("arguments"))

    if grant != "PERMIT":
        return Violation(
            message=(
                f"TACACS command set '{set_name}' command[{index}] grant "
                f"'{grant}' is not PERMIT ({source})."
            ),
            path=path,
            details={
                "command_set": set_name,
                "index": index,
                "grant": grant,
                "command": command,
                "arguments": arguments,
                "source": source,
            },
        )

    if not _COMMAND_RE.fullmatch(command) or " " in command:
        return Violation(
            message=(
                f"TACACS command set '{set_name}' command[{index}] command "
                f"'{command}' must be a single token (first IOS word only) "
                f"({source})."
            ),
            path=path,
            details={
                "command_set": set_name,
                "index": index,
                "command": command,
                "arguments": arguments,
                "source": source,
            },
        )

    if command not in _ALLOWED_COMMANDS:
        return Violation(
            message=(
                f"TACACS command set '{set_name}' command[{index}] command "
                f"'{command}' is not in the access-switch allowlist ({source})."
            ),
            path=path,
            details={
                "command_set": set_name,
                "index": index,
                "command": command,
                "arguments": arguments,
                "source": source,
            },
        )

    if _REGEX_HINT.search(arguments) or not _ARGS_RE.fullmatch(arguments):
        return Violation(
            message=(
                f"TACACS command set '{set_name}' command[{index}] arguments "
                f"{arguments!r} are not ISE-legal ({source}). ISE ERS wants "
                "literal tokens and optional *; no parentheses or regex."
            ),
            path=path,
            details={
                "command_set": set_name,
                "index": index,
                "command": command,
                "arguments": arguments,
                "source": source,
            },
        )
    return None


def _iter_commands(entry: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not entry:
        return []
    commands = entry.get("commands") or []
    if not isinstance(commands, list):
        return []
    return [c for c in commands if isinstance(c, dict)]


class Rule(RuleBase):
    id = "103"
    description = (
        "TACACS command-set arguments must be ISE ERS literals (* wildcard), "
        "not PCRE; command is the first word only; grant PERMIT"
    )
    severity = "HIGH"
    title = "TACACS COMMAND ARGUMENTS ISE LEGAL"
    affected_items_label = "Illegal commands"
    explanation = """\
ISE ERS TACACS command sets reject PCRE in arguments (HTTP 400, generic
Application resource validation exception). command is the first IOS word
(show, ping, …). arguments are the remaining words; * is the wildcard.
Parentheses such as ver(sion)?.* are illegal. grant must be PERMIT.
Terraform yamldecodes command_sets.yaml into ise_tacacs_command_set."""
    recommendation = """\
Rewrite commands in command_sets.yaml. Example: command show, arguments
version; command show, arguments "ip interface brief"; command ping,
arguments "*". Rebuild nac.yaml with python3 scripts/generate_nac.py."""
    references = [
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/tacacs_command_set",
        "https://github.com/netascode/nac-validate",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        seen: set[tuple[str, str, int, str]] = set()

        def add(v: Violation | None) -> None:
            if v is None:
                return
            key = (
                str(v.details.get("command_set", "")),
                str(v.details.get("source", "")),
                int(v.details.get("index", -1)),
                str(v.details.get("arguments", "")),
            )
            if key in seen:
                return
            seen.add(key)
            violations.append(v)

        file_defs = _tf.command_set_defs()
        for name, entry in file_defs.items():
            for i, cmd in enumerate(_iter_commands(entry)):
                add(
                    _check_command(
                        name, i, cmd, "command_sets.yaml", "command_sets.yaml"
                    )
                )

        for item in data.get("command_sets") or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            for i, cmd in enumerate(_iter_commands(item)):
                add(
                    _check_command(
                        name,
                        i,
                        cmd,
                        f"command_sets[name={name}].commands[{i}]",
                        "nac.yaml",
                    )
                )

        return violations
