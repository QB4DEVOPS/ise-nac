"""FAIL unless wired 802.1X + MAB Network Access policy matches the CoS lock.

Checks YAML/CSV sources and the Terraform that POSTs to ISE. Device Admin
TACACS stays as-is. No guest. No MAC list. endpoint_count stays 0.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

import yaml
from nac_validate import RuleBase, Violation

_ROOT = Path(__file__).resolve().parents[1]
_GROUPS_YAML = _ROOT / "endpoint_identity_groups.yaml"
_PROTOCOLS_YAML = _ROOT / "allowed_protocols.yaml"
_PROFILES_YAML = _ROOT / "authorization_profiles.yaml"
_POLICY_YAML = _ROOT / "network_access.yaml"
_AUTHC_CSV = _ROOT / "network_access_authc.csv"
_AUTHZ_CSV = _ROOT / "network_access_authz.csv"
_NA_TF = _ROOT / "network_access.tf"
_NADS_TF = _ROOT / "nads.tf"
_VARS_TF = _ROOT / "variables.tf"
_MAIN_TF = _ROOT / "main.tf"

_LOCKED_GROUPS = ("Workstation", "IP-Phone", "Printer")
_GUEST_RE = re.compile(r"guest", re.I)
_ENDPOINT_RES = re.compile(r'resource\s+"ise_endpoint"\s+')
_NA_POLICY_RES = re.compile(r'resource\s+"ise_network_access_policy_set"\s+"([^"]+)"')
_DA_POLICY_RES = re.compile(r'resource\s+"ise_device_admin_policy_set"\s+"([^"]+)"')
_ALLOWED_RES = re.compile(r'resource\s+"ise_allowed_protocols"\s+')
_ALLOWED_TACACS_RES = re.compile(r'resource\s+"ise_allowed_protocols_tacacs"\s+')
_AUTHC_RANK = re.compile(r'resource\s+"ise_network_access_authentication_rule_update_ranks"')
_AUTHZ_RANK = re.compile(r'resource\s+"ise_network_access_authorization_rule_update_ranks"')
_NAD_PROTO = re.compile(r'authentication_network_protocol\s+=\s+"RADIUS"')
_NAD_TACACS_SECRET = re.compile(r"tacacs_shared_secret\s+=")
_ENDPOINT_DEFAULT = re.compile(r'variable\s+"endpoint_count"[\s\S]*?default\s+=\s+0', re.M)


def _load_yaml(path: Path, key: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    items = raw.get(key) or []
    return [i for i in items if isinstance(i, dict)]


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _names(items: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for item in items:
        name = item.get("name")
        if isinstance(name, str) and name:
            out.append(name)
    return out


class Rule(RuleBase):
    id = "107"
    description = (
        "Wired 802.1X + MAB: three empty endpoint groups, two Allowed "
        "Protocols, ACCESS_ACCEPT VLANs 10/20/30, one Network Access policy set"
    )
    severity = "HIGH"
    title = "WIRED 802.1X AND MAB NETWORK ACCESS POLICY LOCK"
    affected_items_label = "Network Access policy"
    explanation = """\
CoS lock for wired 802.1X + MAB on CiscoDevNet/ise 0.3.4. Endpoint identity
groups only (Workstation, IP-Phone, Printer). No MAC list. No guest. Two
Allowed Protocols (ise_allowed_protocols): 802.1X EAP and MAB PAP/ASCII.
Authorization profiles ACCESS_ACCEPT with lab VLAN 10 data, 20 voice, 30 MAB.
One Network Access policy set (not Device Admin). Dot1X → Internal Users.
MAB → Internal Endpoints continue-if-not-found. Authorization first-match
with rank-update resources."""
    recommendation = """\
Keep endpoint_count=0. Do not add guest or ise_endpoint MAC rows. Keep
TACACS Device Admin (*_cs / *_shell) unchanged. NAD protocol is RADIUS;
keep both NAD_TACACS_SECRET and NAD_RADIUS_SECRET."""
    references = [
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/endpoint_identity_group",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/allowed_protocols",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/authorization_profile",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/network_access_policy_set",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/network_access_authentication_rule",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/network_access_authorization_rule",
    ]

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        if not isinstance(data, dict):
            data = {}

        violations: list[Violation] = []

        def add(message: str, path: str, name: str = "") -> None:
            violations.append(
                Violation(
                    message=message,
                    path=path,
                    details={"name": name, "kind": "network_access", "source": path},
                )
            )

        groups = _load_yaml(_GROUPS_YAML, "endpoint_identity_groups")
        group_names = _names(groups)
        if tuple(group_names) != _LOCKED_GROUPS:
            add(
                "endpoint_identity_groups.yaml must be exactly Workstation, "
                f"IP-Phone, Printer (got {group_names}). No guest. No MAC list.",
                "endpoint_identity_groups.yaml",
            )
        for g in groups:
            if g.get("system_defined") is True:
                add(
                    f"Endpoint identity group '{g.get('name')}' must not be system_defined.",
                    "endpoint_identity_groups.yaml",
                    str(g.get("name") or ""),
                )

        if "Guest" in group_names or any(_GUEST_RE.search(n) for n in group_names):
            add("Guest endpoint identity groups are not in this phase.", "endpoint_identity_groups.yaml")

        protocols = _load_yaml(_PROTOCOLS_YAML, "allowed_protocols")
        proto_by_name = {p.get("name"): p for p in protocols}
        if set(proto_by_name) != {"Wired_8021X", "Wired_MAB"}:
            add(
                "allowed_protocols.yaml must define exactly Wired_8021X and Wired_MAB "
                f"(got {sorted(proto_by_name)}). ise_allowed_protocols, not TACACS.",
                "allowed_protocols.yaml",
            )
        dot1x = proto_by_name.get("Wired_8021X") or {}
        mab = proto_by_name.get("Wired_MAB") or {}
        if dot1x and not (
            dot1x.get("allow_eap_tls")
            and dot1x.get("allow_peap")
            and not dot1x.get("allow_pap_ascii")
        ):
            add(
                "Wired_8021X must allow EAP-TLS/PEAP and not PAP/ASCII.",
                "allowed_protocols.yaml",
                "Wired_8021X",
            )
        if mab and not (
            mab.get("process_host_lookup")
            and mab.get("allow_pap_ascii")
            and not mab.get("allow_eap_tls")
            and not mab.get("allow_peap")
        ):
            add(
                "Wired_MAB must be Host Lookup + PAP/ASCII with EAP methods off.",
                "allowed_protocols.yaml",
                "Wired_MAB",
            )

        profiles = _load_yaml(_PROFILES_YAML, "authorization_profiles")
        prof_by_name = {p.get("name"): p for p in profiles}
        expect_vlan = {
            "Wired_Data": ("10", False),
            "Wired_Voice": ("20", True),
            "Wired_Printer": ("30", False),
        }
        if set(prof_by_name) != set(expect_vlan):
            add(
                "authorization_profiles.yaml must define Wired_Data, Wired_Voice, "
                f"Wired_Printer (got {sorted(prof_by_name)}).",
                "authorization_profiles.yaml",
            )
        for name, (vlan, voice) in expect_vlan.items():
            p = prof_by_name.get(name) or {}
            if p.get("access_type") != "ACCESS_ACCEPT":
                add(
                    f"Authorization profile '{name}' access_type must be ACCESS_ACCEPT "
                    "(0.3.4 ise_authorization_profile.access_type).",
                    "authorization_profiles.yaml",
                    name,
                )
            if str(p.get("vlan_name_id")) != vlan:
                add(
                    f"Authorization profile '{name}' vlan_name_id must be {vlan} "
                    "(0.3.4 ise_authorization_profile.vlan_name_id).",
                    "authorization_profiles.yaml",
                    name,
                )
            if bool(p.get("voice_domain_permission")) != voice:
                add(
                    f"Authorization profile '{name}' voice_domain_permission must be {voice}.",
                    "authorization_profiles.yaml",
                    name,
                )
            if "dacl_name" in p:
                add(
                    f"Authorization profile '{name}' must not set dacl_name "
                    "(no DACL objects in Git; 0.3.4 field exists but is unused).",
                    "authorization_profiles.yaml",
                    name,
                )

        sets = _load_yaml(_POLICY_YAML, "network_access_policy_sets")
        if len(sets) != 1:
            add(
                "network_access.yaml must list exactly one Network Access policy set "
                f"(got {len(sets)}). Not Device Admin.",
                "network_access.yaml",
            )
        elif sets[0].get("service_name") != "Wired_8021X":
            add(
                "The Network Access policy set service_name must be Wired_8021X "
                "(0.3.4 service_name binds one Allowed Protocols name).",
                "network_access.yaml",
                str(sets[0].get("name") or ""),
            )

        authc = _load_csv(_AUTHC_CSV)
        if [r.get("name") for r in authc] != ["Dot1X", "MAB"]:
            add(
                "network_access_authc.csv must be Dot1X then MAB in ISE push order.",
                "network_access_authc.csv",
            )
        else:
            dot = authc[0]
            mab_row = authc[1]
            if "Internal Users" not in (dot.get("identity_source") or ""):
                add("Dot1X identity_source must map to Internal Users.", "network_access_authc.csv", "Dot1X")
            if "Internal Endpoints" not in (mab_row.get("identity_source") or ""):
                add(
                    "MAB identity_source must map to Internal Endpoints.",
                    "network_access_authc.csv",
                    "MAB",
                )
            if mab_row.get("if_user_not_found") != "CONTINUE":
                add("MAB if_user_not_found must be CONTINUE.", "network_access_authc.csv", "MAB")

        authz = _load_csv(_AUTHZ_CSV)
        authz_groups = [r.get("endpoint_identity_group") for r in authz]
        if authz_groups != ["IP-Phone", "Workstation", "Printer"]:
            add(
                "network_access_authz.csv first-match order must be IP-Phone, "
                f"Workstation, Printer (got {authz_groups}). No guest.",
                "network_access_authz.csv",
            )
        if any(_GUEST_RE.search(str(v)) for row in authz for v in row.values()):
            add("network_access_authz.csv must not mention guest.", "network_access_authz.csv")

        na_tf = _NA_TF.read_text(encoding="utf-8") if _NA_TF.is_file() else ""
        nads_tf = _NADS_TF.read_text(encoding="utf-8") if _NADS_TF.is_file() else ""
        vars_tf = _VARS_TF.read_text(encoding="utf-8") if _VARS_TF.is_file() else ""
        main_tf = _MAIN_TF.read_text(encoding="utf-8") if _MAIN_TF.is_file() else ""

        if not _NA_TF.is_file():
            add("network_access.tf is missing.", "network_access.tf")
        na_sets = _NA_POLICY_RES.findall(na_tf)
        if len(na_sets) != 1:
            add(
                "network_access.tf must declare exactly one ise_network_access_policy_set "
                f"(got {na_sets}).",
                "network_access.tf",
            )
        if _ENDPOINT_RES.search(na_tf) or _ENDPOINT_RES.search(main_tf) or _ENDPOINT_RES.search(nads_tf):
            add(
                "ise_endpoint must not be declared. Groups only; endpoint_count=0. "
                "0.3.4 has ise_endpoint; this phase does not use it.",
                "network_access.tf",
            )
        if not _ALLOWED_RES.search(na_tf):
            add(
                "network_access.tf must use ise_allowed_protocols (0.3.4 Network Access). "
                "Do not fake a resource name.",
                "network_access.tf",
            )
        if _ALLOWED_TACACS_RES.search(na_tf):
            add(
                "Network Access Allowed Protocols are ise_allowed_protocols, not "
                "ise_allowed_protocols_tacacs (that stays Device Admin in main.tf).",
                "network_access.tf",
            )
        if not _AUTHC_RANK.search(na_tf) or not _AUTHZ_RANK.search(na_tf):
            add(
                "Rank-update resources must exist: "
                "ise_network_access_authentication_rule_update_ranks and "
                "ise_network_access_authorization_rule_update_ranks "
                "(same pattern as TACACS device-admin rank updates).",
                "network_access.tf",
            )
        if not _DA_POLICY_RES.search(main_tf):
            add(
                "Keep TACACS Device Admin: main.tf must still declare "
                "ise_device_admin_policy_set.",
                "main.tf",
            )
        if 'name             = "test_cs"' not in main_tf and 'name = "test_cs"' not in main_tf:
            add("Keep the TACACS GUI canary test_cs.", "main.tf")
        if not _NAD_PROTO.search(nads_tf):
            add(
                'NAD authentication_network_protocol must be "RADIUS" '
                "(0.3.4 choices: RADIUS | TACACS_PLUS) so 802.1X can use the NAD.",
                "nads.tf",
            )
        if not _NAD_TACACS_SECRET.search(nads_tf):
            add("Keep tacacs_shared_secret on NADs.", "nads.tf")
        if not _ENDPOINT_DEFAULT.search(vars_tf):
            add("variable endpoint_count default must stay 0.", "variables.tf")

        blob = "\n".join(
            [
                _GROUPS_YAML.read_text(encoding="utf-8") if _GROUPS_YAML.is_file() else "",
                _PROTOCOLS_YAML.read_text(encoding="utf-8") if _PROTOCOLS_YAML.is_file() else "",
                _PROFILES_YAML.read_text(encoding="utf-8") if _PROFILES_YAML.is_file() else "",
                _POLICY_YAML.read_text(encoding="utf-8") if _POLICY_YAML.is_file() else "",
                na_tf,
            ]
        )
        # Comments may mention "no guest"; fail only on guest as a name/resource.
        if re.search(r'\b(name|identity_group|endpoint_identity_group)\b[^:\n]*:\s*["\']?Guest', blob, re.I):
            add("Guest is not in this phase.", "network_access")

        data_groups = data.get("endpoint_identity_groups")
        if isinstance(data_groups, list) and data_groups:
            data_names = _names([i for i in data_groups if isinstance(i, dict)])
            if data_names and tuple(data_names) != _LOCKED_GROUPS:
                add(
                    "nac.yaml endpoint_identity_groups must match Workstation, "
                    f"IP-Phone, Printer (got {data_names}).",
                    "endpoint_identity_groups",
                )

        return violations
