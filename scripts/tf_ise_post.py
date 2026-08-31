"""Resolve TACACS names and command sets Terraform actually POSTs to ISE.

nac.yaml can drift from apply. Terraform csvdecodes tacacs_authz.csv, then
sets command-set name = local.ise_tacacs_name[each.value] (hyphen → underscore)
and profile name = local.ise_tacacs_shell_profile_name[each.value]
({name}_shell — ISE ERS shares one namespace with command sets),
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


def _maps_shell_profile_suffix() -> bool:
    """True when locals.tf sets profile ISE names to {name}_shell.

    The map value is ``${local.ise_tacacs_name[n]}_shell``, so a ``}`` from the
    interpolation sits before ``_shell``. Do not use ``[^}]*``.
    """
    return bool(
        re.search(
            r"ise_tacacs_shell_profile_name\s*=\s*\{[\s\S]{0,500}?_shell",
            _tf_text(),
        )
    )


def _resource_name_uses_local(resource_type: str, local_attr: str) -> bool:
    """True when the ladder resource name uses local.<local_attr>[...].

    Skips the GUI canary (resource address ``test``).
    """
    text = MAIN_TF.read_text(encoding="utf-8") if MAIN_TF.is_file() else ""
    for m in _RESOURCE.finditer(text):
        if m.group(1) != resource_type:
            continue
        if m.group(2) == "test":
            continue
        block = _brace_block(text, m.end() - 1)
        return bool(
            re.search(rf"name\s*=\s*local\.{re.escape(local_attr)}\[", block)
        )
    return False


def _resource_posts_mapped_name(resource_type: str) -> bool:
    """True when the resource name attribute uses local.ise_tacacs_name."""
    return _resource_name_uses_local(resource_type, "ise_tacacs_name")


def literal_resource_names(resource_type: str) -> list[tuple[str, str]]:
    """Hardcoded name = \"...\" on a resource (the GUI canary named test)."""
    text = MAIN_TF.read_text(encoding="utf-8") if MAIN_TF.is_file() else ""
    out: list[tuple[str, str]] = []
    for m in _RESOURCE.finditer(text):
        if m.group(1) != resource_type:
            continue
        block = _brace_block(text, m.end() - 1)
        nm = re.search(r'\bname\s*=\s*"([^"]+)"', block)
        if not nm:
            continue
        name = nm.group(1)
        path = (
            f"main.tf:resource.{resource_type}.{m.group(2)} "
            f"(Terraform POSTs {name!r})"
        )
        out.append((name, path))
    return out


def posted_records(kind: str) -> list[dict[str, str]]:
    """Unique TACACS objects Terraform POSTs to ISE.

    kind is ``command_set`` or ``shell_profile``.
    Each record has csv_key, ise_name, path.
    Command-set ISE names use local.ise_tacacs_name (hyphen → underscore).
    Profile ISE names use local.ise_tacacs_shell_profile_name ({name}_shell)
    when Terraform actually wires that map onto ise_tacacs_profile.name.
    """
    cols = local_csv_columns()
    column = cols["command_sets"] if kind == "command_set" else cols["shell_profiles"]
    resource_type = (
        "ise_tacacs_command_set" if kind == "command_set" else "ise_tacacs_profile"
    )
    hyphen = _maps_hyphen_to_underscore()
    uses_suffix = False
    uses_hyphen_map = False
    map_label = "local.ise_tacacs_name"
    if kind == "shell_profile":
        uses_suffix = _maps_shell_profile_suffix() and _resource_name_uses_local(
            resource_type, "ise_tacacs_shell_profile_name"
        )
        uses_hyphen_map = uses_suffix or (
            hyphen and _resource_name_uses_local(resource_type, "ise_tacacs_name")
        )
        if uses_suffix:
            map_label = "local.ise_tacacs_shell_profile_name"
    else:
        uses_hyphen_map = hyphen and _resource_name_uses_local(
            resource_type, "ise_tacacs_name"
        )

    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for i, row in enumerate(read_authz_csv(), start=2):
        raw = (row.get(column) or "").strip()
        if not raw:
            continue
        ise_name = raw.replace("-", "_") if uses_hyphen_map else raw
        if uses_suffix:
            ise_name = f"{ise_name}_shell"
        if ise_name in seen:
            continue
        seen.add(ise_name)
        src = f"tacacs_authz.csv:{column}:line {i}"
        if ise_name != raw:
            src = f"{src} -> {map_label}"
        src = f"{src} (Terraform POSTs {ise_name!r})"
        out.append({"csv_key": raw, "ise_name": ise_name, "path": src})
    return out


def posted_names(kind: str) -> list[tuple[str, str]]:
    """Unique names Terraform POSTs to ISE.

    kind is ``command_set`` or ``shell_profile``.
    Returns (ise_name, source_path) in first-seen order.
    """
    return [(r["ise_name"], r["path"]) for r in posted_records(kind)]


def yaml_lookup_keys(
    kind: str, ise_name: str, csv_key: str | None = None
) -> list[str]:
    """YAML ``name:`` keys that may hold session_attributes / commands.

    CSV/YAML tier keys stay T1; profile ISE names are T1_shell.
    """
    keys: list[str] = []
    if csv_key:
        keys.append(csv_key.replace("-", "_"))
        if csv_key not in keys:
            keys.append(csv_key)
    keys.append(ise_name)
    if kind == "shell_profile" and ise_name.endswith("_shell"):
        stem = ise_name[: -len("_shell")]
        if stem and stem not in keys:
            keys.append(stem)
    seen: set[str] = set()
    out: list[str] = []
    for key in keys:
        if key and key not in seen:
            seen.add(key)
            out.append(key)
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
    # Skip the GUI canary (ise_tacacs_command_set.test). Inspect the ladder.
    chosen = None
    first_ladder = None
    for m in _RESOURCE.finditer(text):
        if m.group(1) != "ise_tacacs_command_set":
            continue
        if m.group(2) == "test":
            continue
        if first_ladder is None:
            first_ladder = m
        if m.group(2) == "this":
            chosen = m
            break
    m = chosen or first_ladder
    if m is None:
        return result
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
    return result


def profile_resource() -> dict[str, Any]:
    """Attributes of resource ise_tacacs_profile that Terraform POSTs.

    CiscoDevNet/ise 0.3.4 session_attributes nested schema:
    type (MANDATORY|OPTIONAL), name, value.
    """
    text = MAIN_TF.read_text(encoding="utf-8") if MAIN_TF.is_file() else ""
    tf_all = _tf_text()
    result: dict[str, Any] = {
        "has_session_attributes": False,
        "type_mandatory": False,
        "name_priv_lvl": False,
        "uses_shell_profiles_yaml": "shell_profiles.yaml" in tf_all,
        "path": "main.tf:ise_tacacs_profile",
    }
    for m in _RESOURCE.finditer(text):
        if m.group(1) != "ise_tacacs_profile":
            continue
        block = _brace_block(text, m.end() - 1)
        result["has_session_attributes"] = bool(
            re.search(r"\bsession_attributes\s*=", block)
        )
        result["type_mandatory"] = bool(
            re.search(r'type\s*=\s*"MANDATORY"|type\s*=\s*a\.type', block)
        )
        result["name_priv_lvl"] = bool(
            re.search(r'name\s*=\s*"priv-lvl"|name\s*=\s*a\.name', block)
        )
        result["path"] = f"main.tf:resource.ise_tacacs_profile.{m.group(2)}"
        break
    return result
