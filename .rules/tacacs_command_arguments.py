"""FAIL if TACACS command arguments contain regex metacharacters.

Plain words and * only. Parentheses, ?, |, ., +, ^, $, [], {}, \\ 400 on
ISE ERS apply. This rule is fail-closed: missing or unreadable
command_sets.yaml is a violation. nac-validate exit 0 cannot skip this check.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from nac_validate import RuleBase, Violation

_ROOT = Path(__file__).resolve().parents[1]
_COMMAND_SETS_YAML = _ROOT / "command_sets.yaml"
_HELPER = _ROOT / "scripts" / "tf_ise_post.py"
_spec = importlib.util.spec_from_file_location("tf_ise_post", _HELPER)
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {_HELPER}")
_tf = importlib.util.module_from_spec(_spec)
sys.modules["tf_ise_post"] = _tf
_spec.loader.exec_module(_tf)

# ISE ERS arguments: letters, digits, underscore, hyphen, space, * wildcard.
_ALLOWED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_ -*")
# Parentheses, ?, |, and similar regex metacharacters. * is the ISE wildcard.
_REGEX_META = set("()[]{}|^$?+.\\")

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
_T4 = frozenset({"T4", "T4_cs"})


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _iter_commands(entry: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not entry:
        return []
    commands = entry.get("commands") or []
    if not isinstance(commands, list):
        return []
    return [c for c in commands if isinstance(c, dict)]


def _regex_chars(arguments: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for ch in arguments:
        if ch in _REGEX_META and ch not in seen:
            seen.add(ch)
            found.append(ch)
    return found


def _illegal_chars(arguments: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for ch in arguments:
        if ch not in _ALLOWED and ch not in seen:
            seen.add(ch)
            found.append(ch)
    return found


def _check_arguments(
    set_name: str,
    index: int,
    cmd: dict[str, Any],
    path: str,
    source: str,
) -> list[Violation]:
    """Always inspect arguments for regex. Also flag non-PERMIT / non-token command."""
    out: list[Violation] = []
    grant = _as_str(cmd.get("grant")).upper()
    command = _as_str(cmd.get("command")).strip()
    arguments = _as_str(cmd.get("arguments"))

    meta = _regex_chars(arguments)
    other = [c for c in _illegal_chars(arguments) if c not in _REGEX_META]
    if meta or other:
        shown = " ".join(repr(c) for c in meta + other)
        out.append(
            Violation(
                message=(
                    f"TACACS command set '{set_name}' command[{index}] arguments "
                    f"{arguments!r} contain regex/illegal characters {shown} "
                    f"({source}). ISE ERS allows plain words and * only "
                    "(no parentheses, ?, |, or similar). This 400s on apply."
                ),
                path=path,
                details={
                    "command_set": set_name,
                    "index": index,
                    "command": command,
                    "arguments": arguments,
                    "regex_chars": meta,
                    "source": source,
                },
            )
        )

    if grant != "PERMIT":
        out.append(
            Violation(
                message=(
                    f"TACACS command set '{set_name}' command[{index}] grant "
                    f"'{grant}' is not PERMIT ({source})."
                ),
                path=path,
                details={
                    "command_set": set_name,
                    "index": index,
                    "grant": grant,
                    "source": source,
                },
            )
        )

    if (not command) or (" " in command) or (command not in _ALLOWED_COMMANDS):
        out.append(
            Violation(
                message=(
                    f"TACACS command set '{set_name}' command[{index}] command "
                    f"'{command}' must be a single plain IOS word from the "
                    f"access-switch list ({source})."
                ),
                path=path,
                details={
                    "command_set": set_name,
                    "index": index,
                    "command": command,
                    "source": source,
                },
            )
        )
    return out


def _load_command_sets_yaml() -> tuple[list[dict[str, Any]], list[Violation]]:
    """Fail closed: cannot prove arguments are regex-free if the file is unreadable."""
    if not _COMMAND_SETS_YAML.is_file():
        return [], [
            Violation(
                message=(
                    "command_sets.yaml is missing. Cannot prove TACACS arguments "
                    "contain no regex. nac-validate fails closed."
                ),
                path="command_sets.yaml",
                details={"source": "command_sets.yaml", "fail_closed": True},
            )
        ]
    try:
        import yaml
    except ImportError:
        return [], [
            Violation(
                message=(
                    "PyYAML is not installed. Cannot parse command_sets.yaml to "
                    "prove arguments contain no regex. nac-validate fails closed."
                ),
                path="command_sets.yaml",
                details={"source": "command_sets.yaml", "fail_closed": True},
            )
        ]
    try:
        raw = yaml.safe_load(_COMMAND_SETS_YAML.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — fail closed on any parse error
        return [], [
            Violation(
                message=(
                    f"command_sets.yaml could not be parsed ({exc}). "
                    "Cannot prove arguments contain no regex. Fail closed."
                ),
                path="command_sets.yaml",
                details={"source": "command_sets.yaml", "fail_closed": True},
            )
        ]
    if not isinstance(raw, dict):
        return [], [
            Violation(
                message=(
                    "command_sets.yaml is not a mapping. Cannot prove arguments "
                    "contain no regex. Fail closed."
                ),
                path="command_sets.yaml",
                details={"source": "command_sets.yaml", "fail_closed": True},
            )
        ]
    items = raw.get("command_sets")
    if not isinstance(items, list):
        return [], [
            Violation(
                message=(
                    "command_sets.yaml has no command_sets list. Cannot prove "
                    "arguments contain no regex. Fail closed."
                ),
                path="command_sets.yaml",
                details={"source": "command_sets.yaml", "fail_closed": True},
            )
        ]
    return [i for i in items if isinstance(i, dict)], []


class Rule(RuleBase):
    id = "103"
    description = (
        "FAIL if TACACS command arguments contain regex metacharacters "
        "(parentheses, ?, |, or similar); plain words and * only"
    )
    severity = "HIGH"
    title = "TACACS ARGUMENTS MUST NOT CONTAIN REGEX"
    affected_items_label = "Regex arguments"
    explanation = """\
ISE ERS TACACS command-set arguments are not PCRE. Parentheses, ?, |, .*,
and similar metacharacters return HTTP 400 (generic Application resource
validation exception). arguments may be plain words, spaces, hyphens, and
the ISE wildcard *. This rule always reads command_sets.yaml (what
Terraform POSTs). If that file is missing or unreadable, the rule FAILS
closed so nac-validate exit 0 cannot lie."""
    recommendation = """\
Use command = first word, arguments = remaining words with optional *.
Illegal: ver(sion)?.*  ip int(erface)? br(ief)?.*  .*
Legal: version  ip interface brief  *  access vlan *
Rebuild nac.yaml with python3 scripts/generate_nac.py."""
    references = [
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/tacacs_command_set",
        "https://github.com/netascode/nac-validate",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        seen: set[tuple[str, str, int, str, str]] = set()

        def add(v: Violation) -> None:
            key = (
                str(v.details.get("command_set", "")),
                str(v.details.get("source", "")),
                int(v.details.get("index", -1)),
                str(v.details.get("arguments", "")),
                v.message[:80],
            )
            if key in seen:
                return
            seen.add(key)
            violations.append(v)

        file_items, load_violations = _load_command_sets_yaml()
        for v in load_violations:
            add(v)

        scanned = 0
        for item in file_items:
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            for i, cmd in enumerate(_iter_commands(item)):
                scanned += 1
                for v in _check_arguments(
                    name, i, cmd, "command_sets.yaml", "command_sets.yaml"
                ):
                    add(v)

        posted = [name for name, _ in _tf.posted_names("command_set") if name not in _T4]
        if posted and not load_violations and scanned == 0:
            add(
                Violation(
                    message=(
                        "Terraform POSTs non-T4 command sets but command_sets.yaml "
                        "has no commands to inspect. Cannot prove arguments contain "
                        "no regex. Fail closed."
                    ),
                    path="command_sets.yaml",
                    details={"source": "command_sets.yaml", "fail_closed": True},
                )
            )

        for item in data.get("command_sets") or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            for i, cmd in enumerate(_iter_commands(item)):
                for v in _check_arguments(
                    name,
                    i,
                    cmd,
                    f"command_sets[name={name}].commands[{i}].arguments",
                    "nac.yaml",
                ):
                    add(v)

        return violations
