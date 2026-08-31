"""ISE TACACS profiles must POST session_attributes (not an empty profile).

CiscoDevNet/ise 0.3.4 ise_tacacs_profile nested schema:
  type = MANDATORY | OPTIONAL
  name = priv-lvl
  value = 1 (T1, auditor_*) or 15 (everyone else)

Empty profiles 400 on ISE 3.5. T1 and T4 failed create for that reason once.
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

_PRIV1 = frozenset({"T1", "auditor_internal", "auditor_external"})
_PRIV15 = frozenset({"T2", "T3", "T4", "vendor", "contractor"})


def _attrs(entry: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not entry:
        return []
    items = entry.get("session_attributes") or []
    if not isinstance(items, list):
        return []
    return [a for a in items if isinstance(a, dict)]


def _priv_value(entry: dict[str, Any] | None) -> str | None:
    for a in _attrs(entry):
        if str(a.get("name", "")) == "priv-lvl":
            return str(a.get("value", "")).strip()
    return None


def _check_entry(
    name: str,
    entry: dict[str, Any] | None,
    path: str,
    source: str,
) -> Violation | None:
    attrs = _attrs(entry)
    if not attrs:
        return Violation(
            message=(
                f"TACACS profile '{name}' has no session_attributes ({source}). "
                "ISE 3.5 rejects empty profiles (HTTP 400). POST type=MANDATORY, "
                "name=priv-lvl, value=1 or 15."
            ),
            path=path,
            details={"profile": name, "source": source},
        )

    priv = None
    for a in attrs:
        typ = str(a.get("type", "")).upper()
        attr_name = str(a.get("name", ""))
        value = str(a.get("value", "")).strip()
        if typ not in {"MANDATORY", "OPTIONAL"}:
            return Violation(
                message=(
                    f"TACACS profile '{name}' session attribute type '{typ}' "
                    f"is not MANDATORY or OPTIONAL ({source}). CiscoDevNet/ise "
                    "0.3.4 only allows those two."
                ),
                path=path,
                details={"profile": name, "type": typ, "source": source},
            )
        if attr_name == "priv-lvl":
            if typ != "MANDATORY":
                return Violation(
                    message=(
                        f"TACACS profile '{name}' priv-lvl type must be "
                        f"MANDATORY ({source}), not {typ}."
                    ),
                    path=path,
                    details={"profile": name, "type": typ, "source": source},
                )
            if value not in {"1", "15"}:
                return Violation(
                    message=(
                        f"TACACS profile '{name}' priv-lvl value '{value}' "
                        f"must be 1 or 15 ({source})."
                    ),
                    path=path,
                    details={"profile": name, "value": value, "source": source},
                )
            priv = value

    if priv is None:
        return Violation(
            message=(
                f"TACACS profile '{name}' is missing session attribute "
                f"name=priv-lvl ({source})."
            ),
            path=path,
            details={"profile": name, "source": source},
        )

    if name in _PRIV1 and priv != "1":
        return Violation(
            message=(
                f"TACACS profile '{name}' must use priv-lvl 1 ({source}). "
                "T1 and auditors are read-only."
            ),
            path=path,
            details={"profile": name, "value": priv, "source": source},
        )
    if name in _PRIV15 and priv != "15":
        return Violation(
            message=(
                f"TACACS profile '{name}' must use priv-lvl 15 ({source})."
            ),
            path=path,
            details={"profile": name, "value": priv, "source": source},
        )
    return None


class Rule(RuleBase):
    id = "104"
    description = (
        "TACACS profiles must POST session_attributes type=MANDATORY "
        "name=priv-lvl value=1 (T1/auditor) or 15 (everyone else)"
    )
    severity = "HIGH"
    title = "TACACS PROFILE SESSION ATTRIBUTES"
    affected_items_label = "Profiles"
    explanation = """\
ise_tacacs_profile (CiscoDevNet/ise 0.3.4) POSTs session_attributes as a
list of {type, name, value}. type is MANDATORY or OPTIONAL. Empty profiles
return HTTP 400 on ISE 3.5 (T1 and T4 failed create for that reason).
T1 and auditor_* use priv-lvl 1; T2/T3/T4/vendor/contractor use 15.
Terraform yamldecodes shell_profiles.yaml; this rule also reads main.tf."""
    recommendation = """\
Put session_attributes in shell_profiles.yaml:
  type: MANDATORY
  name: priv-lvl
  value: "1"   # or "15"
Wire them into resource.ise_tacacs_profile.session_attributes in main.tf.
Rebuild nac.yaml with python3 scripts/generate_nac.py."""
    references = [
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/tacacs_profile",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []
        seen: set[tuple[str, str]] = set()

        def add(v: Violation | None) -> None:
            if v is None:
                return
            key = (str(v.details.get("profile", "")), str(v.details.get("source", "")))
            if key in seen:
                return
            seen.add(key)
            violations.append(v)

        resource = _tf.profile_resource()
        posted = _tf.posted_names("shell_profile")
        file_defs = _tf.shell_profile_defs()

        if posted and not resource["has_session_attributes"]:
            for name, _csv_path in posted:
                add(
                    Violation(
                        message=(
                            f"TACACS profile '{name}' is POSTed without "
                            "session_attributes in Terraform. ISE 3.5 rejects "
                            "empty profiles (HTTP 400)."
                        ),
                        path=resource["path"],
                        details={"profile": name, "source": "terraform"},
                    )
                )

        if posted and not (resource["type_mandatory"] and resource["name_priv_lvl"]):
            if resource["has_session_attributes"]:
                add(
                    Violation(
                        message=(
                            "ise_tacacs_profile session_attributes must set "
                            'type = "MANDATORY" (or a.type from YAML) and '
                            'name = "priv-lvl" (or a.name from YAML) per '
                            "CiscoDevNet/ise 0.3.4."
                        ),
                        path=resource["path"],
                        details={"profile": "*", "source": "terraform"},
                    )
                )

        for rec in _tf.posted_records("shell_profile"):
            ise_name = rec["ise_name"]
            csv_path = rec["path"]
            keys = _tf.yaml_lookup_keys("shell_profile", ise_name, rec.get("csv_key"))
            entry = None
            yaml_name = keys[0] if keys else ise_name
            for key in keys:
                if key in file_defs:
                    entry = file_defs[key]
                    yaml_name = key
                    break
            if entry is None:
                add(
                    Violation(
                        message=(
                            f"TACACS profile '{ise_name}' is POSTed from "
                            "tacacs_authz.csv but missing from shell_profiles.yaml "
                            f"(looked up YAML keys {keys})."
                        ),
                        path=csv_path,
                        details={
                            "profile": yaml_name,
                            "ise_name": ise_name,
                            "source": "shell_profiles.yaml",
                        },
                    )
                )
                continue
            add(
                _check_entry(
                    yaml_name, entry, "shell_profiles.yaml", "shell_profiles.yaml"
                )
            )

        for item in data.get("shell_profiles") or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            add(
                _check_entry(
                    name, item, f"shell_profiles[name={name}]", "nac.yaml"
                )
            )

        return violations
