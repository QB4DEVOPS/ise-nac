"""FAIL unless wired 802.1X + MAB Network Access policy matches the CoS lock.

Checks YAML/CSV sources and the Terraform that POSTs to ISE. Device Admin
TACACS stays as-is. No guest. 11 groups × 10 lab MACs = 110.
OUIs are locked IEEE MA-L assignments; last 3 octets are generated.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from nac_validate import RuleBase, Violation

_ROOT = Path(__file__).resolve().parents[1]
_GROUPS_YAML = _ROOT / "endpoint_identity_groups.yaml"
_ENDPOINTS_YAML = _ROOT / "endpoints.yaml"
_ENDPOINTS_CSV = _ROOT / "endpoints.csv"
_ENTERPRISE_CSV = _ROOT / "endpoints_enterprise.csv"
_PROTOCOLS_YAML = _ROOT / "allowed_protocols.yaml"
_PROFILES_YAML = _ROOT / "authorization_profiles.yaml"
_POLICY_YAML = _ROOT / "network_access.yaml"
_AUTHC_CSV = _ROOT / "network_access_authc.csv"
_AUTHZ_CSV = _ROOT / "network_access_authz.csv"
_NA_TF = _ROOT / "network_access.tf"
_NADS_TF = _ROOT / "nads.tf"
_VARS_TF = _ROOT / "variables.tf"
_LOCALS_TF = _ROOT / "locals.tf"
_MAIN_TF = _ROOT / "main.tf"

_LOCKED_GROUPS = (
    "Phones",
    "AP",
    "Printers",
    "TVs",
    "Badge_Readers",
    "Cameras",
    "UPS",
    "Powerstrips",
    "Linux",
    "Windows",
    "RFID_Readers",
)
_REMOVED_GROUPS = ("Workstation", "IP-Phone", "Printer")
_MACS_PER_GROUP = 10
_ENDPOINT_TOTAL = len(_LOCKED_GROUPS) * _MACS_PER_GROUP
_AUTHZ_ORDER = (
    ("phones", "Phones", "Wired_Voice"),
    ("printers", "Printers", "Wired_Printer"),
    ("ap", "AP", "Wired_AP"),
    ("cameras", "Cameras", "Wired_Camera"),
    ("badge_readers", "Badge_Readers", "Wired_Badge"),
    ("rfid_readers", "RFID_Readers", "Wired_Badge"),
    ("ups", "UPS", "Wired_Facilities"),
    ("powerstrips", "Powerstrips", "Wired_Facilities"),
    ("tvs", "TVs", "Wired_Data"),
    ("linux", "Linux", "Wired_Data"),
    ("windows", "Windows", "Wired_Data"),
)
_LOCKED_PROFILES = {
    "Wired_Data": ("10", False),
    "Wired_Voice": ("20", True),
    "Wired_Printer": ("30", False),
    "Wired_AP": ("40", False),
    "Wired_Camera": ("50", False),
    "Wired_Badge": ("60", False),
    "Wired_Facilities": ("70", False),
}
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
_ENDPOINT_DEFAULT = re.compile(r'variable\s+"endpoint_count"[\s\S]*?default\s+=\s+150000', re.M)
_LAB_ENDPOINTS_FILE = re.compile(r'file\("\$\{path\.module\}/endpoints\.csv"\)')
_ENTERPRISE_ENDPOINTS_FILE = re.compile(
    r'file\("\$\{path\.module\}/endpoints_enterprise\.csv"\)'
)
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_ENTERPRISE_GROUP_COUNTS = {
    "Phones": 71000,
    "Windows": 71000,
    "AP": 2250,
    "Printers": 1550,
    "Cameras": 1500,
    "Badge_Readers": 800,
    "TVs": 600,
    "Linux": 500,
    "UPS": 400,
    "Powerstrips": 250,
    "RFID_Readers": 150,
}
_ENTERPRISE_TOTAL = 150000
_LOCKED_OUI = {
    "Phones": "00:04:f2",
    "AP": "9c:e3:30",
    "Printers": "9c:7b:ef",
    "TVs": "64:1b:2f",
    "Badge_Readers": "00:30:8e",
    "Cameras": "00:40:8c",
    "UPS": "00:c0:b7",
    "Powerstrips": "00:0d:5d",
    "Linux": "00:c0:4f",
    "Windows": "10:e7:c6",
    "RFID_Readers": "00:16:25",
}
_ORG_NEEDLES = {
    "Phones": "polycom",
    "AP": "cisco meraki",
    "Printers": "hewlett packard",
    "TVs": "samsung electronics",
    "Badge_Readers": "hid global",
    "Cameras": "axis communications",
    "UPS": "american power conversion",
    "Powerstrips": "raritan",
    "Linux": "dell",
    "Windows": "hewlett packard",
    "RFID_Readers": "impinj",
}


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


def _nic_suffix(mac: str) -> str:
    return ":".join(mac.split(":")[3:])


def _is_trivial_nic_suffix(suffix: str) -> bool:
    parts = suffix.split(":")
    if len(parts) != 3:
        return True
    a, b, c = (int(p, 16) for p in parts)
    if a == 0 and b == 0:
        return True
    if b == 0 and 1 <= c <= 10:
        return True
    return suffix in {"00:00:00", "ff:ff:ff"}


class Rule(RuleBase):
    id = "107"
    description = (
        "Wired 802.1X + MAB: eleven endpoint groups, 110 lab MACs, two Allowed "
        "Protocols, ACCESS_ACCEPT VLANs 10–70, one Network Access policy set"
    )
    severity = "HIGH"
    title = "WIRED 802.1X AND MAB NETWORK ACCESS POLICY LOCK"
    affected_items_label = "Network Access policy"
    explanation = """\
CoS lock for wired 802.1X + MAB on CiscoDevNet/ise 0.3.4. Eleven endpoint
identity groups (Phones, AP, Printers, TVs, Badge_Readers, Cameras, UPS,
Powerstrips, Linux, Windows, RFID_Readers). 10 unique lab MACs per group
(110 total) using locked IEEE MA-L OUIs plus generated last 3 octets.
No 02:00:GG. No 00:00:01–00:00:0A. No guest. No 15k MAC dump. Two Allowed
Protocols (ise_allowed_protocols): 802.1X EAP and MAB PAP/ASCII.
Authorization profiles ACCESS_ACCEPT with lab VLANs 10–70: Wired_Data 10,
Wired_Voice 20 (voice_domain_permission), Wired_Printer 30, Wired_AP 40,
Wired_Camera 50, Wired_Badge 60, Wired_Facilities 70. First-match authz:
Phones → Wired_Voice, Printers → Wired_Printer, AP → Wired_AP,
Cameras → Wired_Camera, Badge_Readers/RFID_Readers → Wired_Badge,
UPS/Powerstrips → Wired_Facilities, TVs/Linux/Windows → Wired_Data.
Not all 11 groups on VLAN 10.
One Network Access policy set (not Device Admin). Dot1X → Internal Users.
MAB → Internal Endpoints continue-if-not-found. Authorization first-match
with rank-update resources. Terraform apply default endpoint_count=150000
from endpoints_enterprise.csv (NDO-225: 71k Phones + 71k Windows desks,
plus 8k of the other 9 groups; no Wi-Fi clients). Lab endpoints.csv /
endpoints.yaml stay 110 (inventory only; not csvdecode'd by Terraform).
Do not apply both."""
    recommendation = """\
Keep endpoint_count default 150000 (all endpoints_enterprise.csv rows).
Groups-only is TF_VAR_endpoint_count=0. Cap with TF_VAR_endpoint_count.
Lab endpoints.csv stays 110 in Git; do not apply it with the 150k file
(Small PAN). Do not add guest. Keep TACACS Device Admin (*_cs / *_shell)
unchanged. NAD protocol is RADIUS; keep both NAD_TACACS_SECRET and
NAD_RADIUS_SECRET."""
    references = [
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/endpoint_identity_group",
        "https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/endpoint",
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
                "endpoint_identity_groups.yaml must be exactly Phones, AP, Printers, "
                f"TVs, Badge_Readers, Cameras, UPS, Powerstrips, Linux, Windows, "
                f"RFID_Readers (got {group_names}). Drop Workstation / IP-Phone / Printer. No guest.",
                "endpoint_identity_groups.yaml",
            )
        for removed in _REMOVED_GROUPS:
            if removed in group_names:
                add(
                    f"Endpoint identity group '{removed}' is gone. Use the CoS lock names.",
                    "endpoint_identity_groups.yaml",
                    removed,
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

        csv_eps = _load_csv(_ENDPOINTS_CSV)
        yaml_eps = _load_yaml(_ENDPOINTS_YAML, "endpoints")
        if not _ENDPOINTS_CSV.is_file():
            add("endpoints.csv is missing (110 lab MACs).", "endpoints.csv")
        if not _ENDPOINTS_YAML.is_file():
            add("endpoints.yaml is missing (110 lab MACs).", "endpoints.yaml")
        if len(csv_eps) != _ENDPOINT_TOTAL:
            add(
                f"endpoints.csv must have {_ENDPOINT_TOTAL} lab MACs "
                f"(11 groups × 10). Got {len(csv_eps)}. No 15k dump.",
                "endpoints.csv",
            )
        if len(yaml_eps) != _ENDPOINT_TOTAL:
            add(
                f"endpoints.yaml must have {_ENDPOINT_TOTAL} lab MACs "
                f"(11 groups × 10). Got {len(yaml_eps)}. No 15k dump.",
                "endpoints.yaml",
            )
        if len(csv_eps) >= 15000 or len(yaml_eps) >= 15000:
            add("Do not dump 15k MACs.", "endpoints.csv")

        csv_macs = [r.get("mac") or "" for r in csv_eps]
        yaml_macs = [r.get("mac") or "" for r in yaml_eps]
        if csv_macs != yaml_macs:
            add("endpoints.csv and endpoints.yaml MAC lists must match.", "endpoints.csv")
        if len(csv_macs) != len(set(csv_macs)):
            add("endpoints.csv MACs must be unique.", "endpoints.csv")

        per_group = Counter(r.get("endpoint_identity_group") for r in csv_eps)
        for name in _LOCKED_GROUPS:
            if per_group.get(name) != _MACS_PER_GROUP:
                add(
                    f"Group '{name}' must have {_MACS_PER_GROUP} lab MACs "
                    f"(got {per_group.get(name)}).",
                    "endpoints.csv",
                    name,
                )
        extra = set(per_group) - set(_LOCKED_GROUPS)
        if extra:
            add(f"endpoints.csv has unknown groups {sorted(extra)}.", "endpoints.csv")

        csv_suffixes = [_nic_suffix(m) for m in csv_macs if m]
        if csv_suffixes and len(csv_suffixes) != len(set(csv_suffixes)):
            add("endpoints.csv last-3-octet suffixes must be unique across 110.", "endpoints.csv")

        for r in csv_eps:
            mac = (r.get("mac") or "").strip()
            group = r.get("endpoint_identity_group") or ""
            if not _MAC_RE.fullmatch(mac):
                add(
                    f"MAC must be lowercase colon hex (got {mac!r}). Lab MAC, not hardware.",
                    "endpoints.csv",
                    mac,
                )
                break
            if mac.startswith("02:00:"):
                add(
                    f"MAC {mac} still uses the dropped 02:00:GG pattern.",
                    "endpoints.csv",
                    mac,
                )
                break
            locked_oui = _LOCKED_OUI.get(group)
            if locked_oui and not mac.startswith(f"{locked_oui}:"):
                add(
                    f"MAC {mac} for {group} must start with locked IEEE MA-L OUI {locked_oui}.",
                    "endpoints.csv",
                    mac,
                )
                break
            if locked_oui and (r.get("oui") or "") != locked_oui:
                add(
                    f"endpoints.csv oui for {group} must be {locked_oui} (got {r.get('oui')!r}).",
                    "endpoints.csv",
                    group,
                )
                break
            org = (r.get("organization") or "").casefold()
            needle = _ORG_NEEDLES.get(group, "")
            if needle and needle not in org:
                add(
                    f"endpoints.csv organization for {group} must cite IEEE org matching "
                    f"{needle!r} (got {r.get('organization')!r}).",
                    "endpoints.csv",
                    group,
                )
                break
            suffix = _nic_suffix(mac)
            if _is_trivial_nic_suffix(suffix):
                add(
                    f"MAC {mac} NIC suffix is trivial (no 00:00:01–00:00:0A, no zero-middle counter).",
                    "endpoints.csv",
                    mac,
                )
                break
            desc = (r.get("description") or "").casefold()
            if "lab" not in desc or "not hardware" not in desc:
                add(
                    f"endpoints.csv description must say lab / not hardware ({mac}).",
                    "endpoints.csv",
                    mac,
                )
                break
            if _GUEST_RE.search(mac) or _GUEST_RE.search(group):
                add("Guest is not in this phase.", "endpoints.csv")
                break

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
        if set(prof_by_name) != set(_LOCKED_PROFILES):
            add(
                "authorization_profiles.yaml must define Wired_Data, Wired_Voice, "
                "Wired_Printer, Wired_AP, Wired_Camera, Wired_Badge, "
                f"Wired_Facilities (got {sorted(prof_by_name)}).",
                "authorization_profiles.yaml",
            )
        for name, (vlan, voice) in _LOCKED_PROFILES.items():
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
            tag = p.get("vlan_tag_id")
            if tag is None or int(tag) != 0:
                add(
                    f"Authorization profile '{name}' vlan_tag_id must be 0 "
                    "(0.3.4 ise_authorization_profile.vlan_tag_id).",
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
        got_authz = [
            (r.get("name"), r.get("endpoint_identity_group"), r.get("profile")) for r in authz
        ]
        if got_authz != list(_AUTHZ_ORDER):
            add(
                "network_access_authz.csv first-match must be Phones→Wired_Voice, "
                "Printers→Wired_Printer, AP→Wired_AP, Cameras→Wired_Camera, "
                "Badge_Readers/RFID_Readers→Wired_Badge, "
                "UPS/Powerstrips→Wired_Facilities, TVs/Linux/Windows→Wired_Data "
                f"(got {got_authz}). Drop Workstation / IP-Phone / Printer. No guest.",
                "network_access_authz.csv",
            )
        if any(_GUEST_RE.search(str(v)) for row in authz for v in row.values()):
            add("network_access_authz.csv must not mention guest.", "network_access_authz.csv")
        for removed in _REMOVED_GROUPS:
            if any(removed == r.get("endpoint_identity_group") for r in authz):
                add(
                    f"Authz must not target removed group '{removed}'.",
                    "network_access_authz.csv",
                    removed,
                )

        na_tf = _NA_TF.read_text(encoding="utf-8") if _NA_TF.is_file() else ""
        nads_tf = _NADS_TF.read_text(encoding="utf-8") if _NADS_TF.is_file() else ""
        vars_tf = _VARS_TF.read_text(encoding="utf-8") if _VARS_TF.is_file() else ""
        locals_tf = _LOCALS_TF.read_text(encoding="utf-8") if _LOCALS_TF.is_file() else ""
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
        if not _ENDPOINT_RES.search(na_tf):
            add(
                "network_access.tf must declare ise_endpoint (0.3.4: name, mac, group_id, "
                "static_group_assignment, static_profile_assignment). 110 lab MACs.",
                "network_access.tf",
            )
        if "group_id" not in na_tf:
            add(
                "ise_endpoint must set group_id from ise_endpoint_identity_group.id "
                "(0.3.4 Identity Group ID).",
                "network_access.tf",
            )
        if "static_group_assignment" not in na_tf or "static_profile_assignment" not in na_tf:
            add(
                "ise_endpoint 0.3.4 requires static_group_assignment and "
                "static_profile_assignment.",
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
            add(
                "variable endpoint_count default must be 150000 "
                "(all endpoints_enterprise.csv rows).",
                "variables.tf",
            )
        if not _ENTERPRISE_ENDPOINTS_FILE.search(locals_tf):
            add(
                "locals.tf must csvdecode endpoints_enterprise.csv for ise_endpoint "
                "(apply path, 150k).",
                "locals.tf",
            )
        if _LAB_ENDPOINTS_FILE.search(locals_tf):
            add(
                "locals.tf must not csvdecode endpoints.csv "
                "(lab 110 is inventory only; do not apply both).",
                "locals.tf",
            )

        if not _ENTERPRISE_CSV.is_file():
            add(
                "endpoints_enterprise.csv is missing (150000 apply-path MACs).",
                "endpoints_enterprise.csv",
            )
        else:
            ent = _load_csv(_ENTERPRISE_CSV)
            if len(ent) != _ENTERPRISE_TOTAL:
                add(
                    f"endpoints_enterprise.csv must have {_ENTERPRISE_TOTAL} rows "
                    f"(got {len(ent)}). Small PAN ceiling. Not 300k. Not lab 110.",
                    "endpoints_enterprise.csv",
                )
            ent_groups = Counter(r.get("endpoint_identity_group") for r in ent)
            for name, want in _ENTERPRISE_GROUP_COUNTS.items():
                if ent_groups.get(name) != want:
                    add(
                        f"endpoints_enterprise.csv group '{name}' must have {want} "
                        f"rows (got {ent_groups.get(name)}). NDO-225 lock.",
                        "endpoints_enterprise.csv",
                        name,
                    )
            extra_ent = set(ent_groups) - set(_ENTERPRISE_GROUP_COUNTS)
            if extra_ent:
                add(
                    f"endpoints_enterprise.csv has unknown groups {sorted(extra_ent)}. "
                    "No Wi-Fi Clients group.",
                    "endpoints_enterprise.csv",
                )
            ent_macs = [r.get("mac") or "" for r in ent]
            if ent_macs and len(ent_macs) != len(set(ent_macs)):
                add(
                    "endpoints_enterprise.csv MACs must be unique across 150000.",
                    "endpoints_enterprise.csv",
                )
            if ent and len(ent) >= 2:
                if (ent[0].get("endpoint_identity_group") != "Phones"
                        or ent[1].get("endpoint_identity_group") != "Windows"):
                    add(
                        "First two enterprise rows must be Phones then Windows (same desk).",
                        "endpoints_enterprise.csv",
                    )
                elif not (
                    ent[0].get("desk")
                    and ent[0].get("desk") == ent[1].get("desk")
                    and ent[0].get("switch") == ent[1].get("switch")
                    and ent[0].get("port") == ent[1].get("port")
                    and ent[0].get("site") == ent[1].get("site")
                ):
                    add(
                        "Phone and PC must share desk, switch, port, and site.",
                        "endpoints_enterprise.csv",
                    )
            if len(ent) > 142000 and (ent[142000].get("desk") or "").strip():
                add(
                    "Non-desk enterprise rows must use an empty desk column.",
                    "endpoints_enterprise.csv",
                )

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
                    "nac.yaml endpoint_identity_groups must match Phones, AP, Printers, "
                    f"TVs, Badge_Readers, Cameras, UPS, Powerstrips, Linux, Windows, "
                    f"RFID_Readers (got {data_names}).",
                    "endpoint_identity_groups",
                )

        data_eps = data.get("endpoints")
        if isinstance(data_eps, list) and data_eps:
            if len(data_eps) != _ENDPOINT_TOTAL:
                add(
                    f"nac.yaml endpoints must be {_ENDPOINT_TOTAL} lab MACs (got {len(data_eps)}).",
                    "endpoints",
                )

        return violations
