"""Resolve TACACS names and command sets Terraform actually POSTs to ISE.

nac.yaml can drift from apply. Terraform csvdecodes tacacs_authz.csv, then
sets resource name = local.ise_tacacs_name[each.value] (hyphen → underscore),
and yamldecodes command_sets.yaml / shell_profiles.yaml.
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
COMMAND_SETS_YAML = ROOT / "command_sets.yaml"
SHELL_PROFILES_YAML = ROOT / "shell_profiles.yaml"

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


def _maps_hyphen_to_underscore() -> bool:
    """True when locals.tf maps CSV names through replace(n, "-", "_")."""
    return bool(
        re.search(
            r"ise_tacacs_name\s*=\s*\{[^}]*replace\(\s*n\s*,\s*\"-\"\s*,\s*\"_\"\s*\)",
            _tf_text(),
            re.S,
        )
    )


def _resource_posts_mapped_name(resource_type: str) -> bool:
    """True when the resource name attribute uses local.ise_tacacs_name."""
    text = MAIN_TF.read_text(encoding="utf-8") if MAIN_TF.is_file() else ""
    for m in _RESOURCE.finditer(text):
        if m.group(1) != resource_type:
            continue
        block = _brace_block(text, m.end() - 1)
        return bool(re.search(r"name\s*=\s*local\.ise_tacacs_name\[", block))
    return False


def posted_names(kind: str) -> list[tuple[str, str]]:
    """Unique names Terraform POSTs to ISE.

    kind is ``command_set`` or ``shell_profile``.
    Returns (name, source_path) in first-seen order.
    Applies locals.ise_tacacs_name (hyphen → underscore) when Terraform does.
    """
    cols = local_csv_columns()
    column = cols["command_sets"] if kind == "command_set" else cols["shell_profiles"]
    resource_type = (
        "ise_tacacs_command_set" if kind == "command_set" else "ise_tacacs_profile"
    )
    mapped = _maps_hyphen_to_underscore() and _resource_posts_mapped_name(resource_type)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for i, row in enumerate(read_authz_csv(), start=2):
        raw = (row.get(column) or "").strip()
        if not raw:
            continue
        name = raw.replace("-", "_") if mapped else raw
        if name in seen:
            continue
        seen.add(name)
        src = f"tacacs_authz.csv:{column}:line {i}"
        if mapped and raw != name:
            src = f"{src} -> local.ise_tacacs_name"
        src = f"{src} (Terraform POSTs {name!r})"
        out.append((name, src))
    return out


def _load_yaml_list(path: Path, key: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        import yaml
    except ImportError:
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return []
    items = data.get(key) or []
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict)]


def command_set_defs() -> dict[str, dict[str, Any]]:
    """Command sets Terraform yamldecodes from command_sets.yaml."""
    out: dict[str, dict[str, Any]] = {}
    for item in _load_yaml_list(COMMAND_SETS_YAML, "command_sets"):
        name = item.get("name")
        if isinstance(name, str) and name:
            out[name] = item
    return out


def shell_profile_defs() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in _load_yaml_list(SHELL_PROFILES_YAML, "shell_profiles"):
        name = item.get("name")
        if isinstance(name, str) and name:
            out[name] = item
    return out


def command_set_resource() -> dict[str, Any]:
    """Attributes of resource ise_tacacs_command_set that Terraform POSTs."""
    text = MAIN_TF.read_text(encoding="utf-8") if MAIN_TF.is_file() else ""
    tf_all = _tf_text()
    result: dict[str, Any] = {
        "permit_unmatched": None,
        "has_commands": False,
        "uses_command_sets_yaml": "command_sets.yaml" in tf_all,
        "path": "main.tf:ise_tacacs_command_set",
    }
    for m in _RESOURCE.finditer(text):
        if m.group(1) != "ise_tacacs_command_set":
            continue
        block = _brace_block(text, m.end() - 1)
        pm = re.search(r"permit_unmatched\s*=\s*(true|false)", block)
        if pm:
            result["permit_unmatched"] = pm.group(1) == "true"
        elif re.search(r"permit_unmatched\s*=", block):
            result["permit_unmatched"] = "per-set"
        result["has_commands"] = bool(
            re.search(r"\bcommands\s*=", block) or re.search(r"\bcommand\s*\{", block)
        )
        result["path"] = f"main.tf:resource.ise_tacacs_command_set.{m.group(2)}"
        break
    return result
