"""Resolve TACACS names Terraform actually POSTs to ISE.

nac.yaml can drift from apply. Terraform csvdecodes tacacs_authz.csv and
sets ise_tacacs_command_set / ise_tacacs_profile name = each.value.
NDG and identity-group hyphens are out of scope.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUTHZ_CSV = ROOT / "tacacs_authz.csv"
LOCALS_TF = ROOT / "locals.tf"
MAIN_TF = ROOT / "main.tf"

_LOCAL_COL = re.compile(
    r"(command_sets|shell_profiles)\s*=\s*toset\(\[\s*"
    r"for\s+row\s+in\s+local\.authz\s*:\s*row\.([A-Za-z0-9_]+)\s*\]\)",
    re.M,
)
_RESOURCE = re.compile(
    r'resource\s+"(ise_tacacs_command_set|ise_tacacs_profile)"\s+"([^"]+)"\s*\{',
    re.M,
)


def read_authz_csv() -> list[dict[str, str]]:
    if not AUTHZ_CSV.is_file():
        return []
    with AUTHZ_CSV.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _tf_text() -> str:
    parts: list[str] = []
    for path in (LOCALS_TF, MAIN_TF):
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _brace_block(text: str, open_at: int) -> str:
    """Return the `{...}` block starting at open_at (index of '{')."""
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at : i + 1]
    return text[open_at:]


def local_csv_columns() -> dict[str, str]:
    """Map terraform local name -> authz CSV column actually used for POSTed names."""
    text = _tf_text()
    found = {m.group(1): m.group(2) for m in _LOCAL_COL.finditer(text)}
    return {
        "command_sets": found.get("command_sets", "command_set"),
        "shell_profiles": found.get("shell_profiles", "shell_profile"),
    }


def posted_names(kind: str) -> list[tuple[str, str]]:
    """Unique names Terraform POSTs.

    kind is ``command_set`` or ``shell_profile``.
    Returns (name, source_path) in first-seen order.
    """
    cols = local_csv_columns()
    column = cols["command_sets"] if kind == "command_set" else cols["shell_profiles"]
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for i, row in enumerate(read_authz_csv(), start=2):
        name = (row.get(column) or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append((name, f"tacacs_authz.csv:{column}:line {i}"))
    return out


def command_set_resource() -> dict[str, Any]:
    """Attributes of resource ise_tacacs_command_set that Terraform POSTs."""
    text = MAIN_TF.read_text(encoding="utf-8") if MAIN_TF.is_file() else ""
    result: dict[str, Any] = {
        "permit_unmatched": None,
        "has_commands": False,
        "path": "main.tf:ise_tacacs_command_set",
    }
    for m in _RESOURCE.finditer(text):
        if m.group(1) != "ise_tacacs_command_set":
            continue
        block = _brace_block(text, m.end() - 1)
        pm = re.search(r"permit_unmatched\s*=\s*(true|false)", block)
        if pm:
            result["permit_unmatched"] = pm.group(1) == "true"
        result["has_commands"] = bool(
            re.search(r"\bcommands\s*=", block) or re.search(r"\bcommand\s*\{", block)
        )
        result["path"] = f"main.tf:resource.ise_tacacs_command_set.{m.group(2)}"
        break
    return result
