# ise-nac

ISE Network as Code: device-admin TACACS plus wired 802.1X/MAB policy.

This PR does **not** apply to ISE. After merge, Robert: pull, load `.env`, `terraform init`, `terraform apply`. Do not apply from an agent.

Robert: use PowerShell in this folder. The command is `terraform` (not `tf`).

## One-time setup

1. Install Terraform from https://developer.hashicorp.com/terraform/install
2. Open PowerShell in this folder.
3. Copy the example env file and put the lab password in `.env` (this file is not in git):

```
copy .env.example .env
notepad .env
```

Change `ISE_PASSWORD=changeme` to the real lab admin password. Set `NAD_TACACS_SECRET`, `NAD_RADIUS_SECRET`, and `USER_PASSWORD_DEFAULT` (empty placeholders in `.env.example`). Save. Close Notepad.

On ISE, turn on **ERS** and **Open API** (Administration → System → Settings → API Settings). Device Admin / TACACS must be licensed.

## Validate YAML before apply

Run this in PowerShell **before** `terraform apply`. Python 3.10+ is required ([install Python](https://www.python.org/downloads/) if `pip` is missing).

```
pip install nac-validate
nac-validate nac.yaml sites.yaml location_ndgs.yaml endpoint_identity_groups.yaml endpoints.yaml allowed_protocols.yaml authorization_profiles.yaml network_access.yaml users.yaml -s .schema.yaml -r .rules
```

That is Cisco Network as Code [`nac-validate`](https://github.com/netascode/nac-validate). `.schema.yaml` checks the shape of `nac.yaml` / `sites.yaml` / `location_ndgs.yaml`, the Network Access YAML, and `users.yaml`. `.rules/` also reads `tacacs_authz.csv`, `command_sets.yaml`, Network Access CSV/YAML, `users.csv`, and Terraform (`local.ise_tacacs_command_set_name` / `local.ise_tacacs_shell_profile_name` in `locals.tf`, commands in `main.tf`, `network_access.tf`, `users.tf`) — the names and commands apply POSTs to ISE, not only `nac.yaml`:

1. TACACS **command-set** and **profile** names may only use letters, digits, underscore, and space. Hyphens fail (`auditor-internal` / `auditor-external`). NDG hyphens (`access-marketing`) stay.
2. Non-T4 command sets must list real IOS commands with `permit_unmatched = false`. T4 may be empty with `permit_unmatched = true`. Empty sets with `permit_unmatched = false` are invalid (HTTP 400).
3. **Rule 103 FAILS** (non-zero exit) if command `arguments` contain regex metacharacters (`(`, `)`, `?`, `|`, `.`, etc.). Plain words and `*` only. Missing `command_sets.yaml` also fails (closed). PCRE such as `ver(sion)?.*` 400s on ISE.
4. Shell profiles POST `session_attributes` (`type=MANDATORY`, `name=priv-lvl`, `value=1` or `15`). Empty profiles 400 on ISE 3.5.
5. **Rule 105 FAILS** if any string is duplicated in the **combined** set of all command-set ISE names and all profile ISE names (one ERS namespace). Every TACACS object is suffixed (underscore only). Command sets: `T1_cs` `T2_cs` `T3_cs` `T4_cs` `vendor_cs` `contractor_cs` `auditor_internal_cs` `auditor_external_cs` `test_cs`. Profiles: `T1_shell` `T2_shell` `T3_shell` `T4_shell` `vendor_shell` `contractor_shell` `auditor_internal_shell` `auditor_external_shell`. No profile named `test_cs`. CSV keys stay `T1`. Identity groups, NDGs, and authz rule names are unchanged.
6. **Rule 106 FAILS** if a user identity group name equals any string in that TACACS bag. Live groups (`T1`, `auditor-internal`) stay; `T1` does not collide with `T1_cs` / `T1_shell`. Suffix an identity group only when it would reuse a command-set or profile ISE name.
7. **Rule 107 FAILS** unless wired 802.1X + MAB stays the CoS lock: eleven endpoint identity groups (Phones, AP, Printers, TVs, Badge_Readers, Cameras, UPS, Powerstrips, Linux, Windows, RFID_Readers). Lab `endpoints.yaml` / `endpoints.csv` stay 10 unique MACs per group (110 total) using locked IEEE MA-L OUIs plus generated last 3 octets. Terraform apply default `endpoint_count` **150000** from `endpoints_enterprise.csv` (not the lab 110 file). No `02:00:GG`. No `00:00:01`–`00:00:0A`. No guest. Two `ise_allowed_protocols` (802.1X EAP and MAB PAP/ASCII). ACCESS_ACCEPT VLANs 10/20/30. Phones → VLAN 20 voice, Printers → VLAN 30 MAB, all other groups → VLAN 10 data. One Network Access policy set (not Device Admin). Dot1X → Internal Users; MAB → Internal Endpoints continue-if-not-found.
8. **Rule 108 FAILS** unless `users.csv` / `users.yaml` is **8** lab Internal Users (one per TACACS identity group: T1, T2, T3, T4, vendor, contractor, `auditor-internal`, `auditor-external`). Terraform resource is `ise_internal_user` (CiscoDevNet/ise **0.3.4**, not `ise_user`). `user_count` default **8**. Secrets stay in `.env` (`USER_PASSWORD_DEFAULT` / `TF_VAR_user_password`). No password column in Git. Not 150k. ERS POSTs one user per create; ISE Internal User store max is 300,000.

If `nac-validate` prints errors, do not apply. Exit 0 means schema and these rules passed. It still does not talk to ISE.

Optional git hook (same check on commit):

```
pip install pre-commit
pre-commit install
```

## Commands

Validate YAML first (`nac-validate` above). Then Terraform.

`terraform init` only downloads the Cisco ISE plugin. The PAN does **not** need to be reachable.

`terraform plan` and `terraform apply` talk to the PAN at `ISE_HOST` (`192.168.1.90`). The PAN must be up. A normal apply (default `nad_count=15000`, `endpoint_count=150000`, `user_count=8`) creates the Location tree, all 15,000 switches, TACACS device-admin, wired 802.1X/MAB policy, **150k enterprise MACs**, **and** 8 lab Internal Users. `.env` must have `NAD_TACACS_SECRET`, `NAD_RADIUS_SECRET`, and `USER_PASSWORD_DEFAULT`.

After merge (Robert, not an agent), paste this in PowerShell (pull, load `.env`, init, apply):

```
git pull
. .\load-env.ps1
terraform init
terraform apply
```

Optional: `terraform plan` before apply. If PowerShell says scripts are disabled, paste this first:

```
Set-ExecutionPolicy -Scope Process Bypass
```

Then paste the block above.

## GUI canary (do not click ISE)

TARS owns the NAC. Terraform creates the GUI test. Robert does not click ISE to make it.

```
. .\load-env.ps1
terraform apply "-target=ise_tacacs_command_set.test"
```

That address is `ise_tacacs_command_set.test`. ISE name is `test_cs`: one command, `show` / `version` / `PERMIT`, `permit_unmatched=false`. No regex. If this 400s, Device Admin / TACACS may not be licensed yet.

## After destroy (rebuild the system)

After `terraform destroy` on pan1, pull this folder and apply. A normal apply builds the **Location tree, all 15,000 NADs, TACACS device-admin, wired 802.1X/MAB policy, 150k enterprise MACs, and 8 lab Internal Users** from Git. After pull, `.env` needs `NAD_TACACS_SECRET`, `NAD_RADIUS_SECRET`, and `USER_PASSWORD_DEFAULT` (never in git). `load-env.ps1` maps them to `TF_VAR_nad_tacacs_secret`, `TF_VAR_nad_radius_secret`, and `TF_VAR_user_password`. There is no secret default in git. Empty TACACS or RADIUS secret with `nad_count>0` fails with a clear error. Empty `USER_PASSWORD_DEFAULT` with `user_count>0` fails with a clear error. NAD `authentication_network_protocol` is `RADIUS` so 802.1X can use the NAD. `tacacs_shared_secret` stays set.

```
git pull
. .\load-env.ps1
terraform init
terraform apply
```

Default `nad_count` is **15000**. You do **not** set `TF_VAR_nad_count` for the full system.

**Warning:** this will take a long time on one PAN. Location NDGs were ~50 seconds each (400 sites + 151 state/country folders + 4 type-level). Then 15,000 NAD creates. Do not apply from an agent. Do not cancel mid-apply if you can avoid it.

A normal apply creates:

- Four Access NDGs from `ndgs.csv`: `access-marketing`, `access-hr`, `access-ceo`, `access-sourcecode`
- Four type-level Location NDGs under ISE All Locations: `regional` (largest-city **type** only), `branch`, plus placeholders `hq` and `dc`. **`regional` is never a state folder name.** NADs do **not** join these type groups.
- One Location folder per US state (`admin1`) and per non-US country (`cc`). One site NDG under that folder: `Location#All Locations#{State}#{site_id}` (example `California#us-los-angeles`). Types stay `regional` / `branch`. No HQ/DC city tags.
- All **15,000** access switches from `devices.csv`
- TACACS authentication sequence from `tacacs_authc.csv`
- TACACS authorization rules from `tacacs_authz.csv` in ISE push order (first match wins)
- Wired 802.1X + MAB Network Access policy (11 endpoint groups, 150k enterprise MACs from `endpoints_enterprise.csv`, no guest)
- 8 lab Internal Users from `users.csv` (one per TACACS identity group). Login/enable secrets from `.env` only.

This does **not** deploy ESXi, an OVA, or C:\Marco paths.

Policy-only (Location tree + TACACS + wired 802.1X/MAB + 150k enterprise MACs + 8 lab Internal Users, **no** switches):

```
. .\load-env.ps1
$env:TF_VAR_nad_count = "0"
terraform apply
```

Groups-only (same, **no** MAC rows): `$env:TF_VAR_endpoint_count = "0"`

Skip Internal User rows (identity groups still apply): `$env:TF_VAR_user_count = "0"`

## NAD inventory (devices.csv)

Default `nad_count` is **15000** — every row in `devices.csv`. `sample_nads.csv` can stay as a tiny optional reference slice; `nad_count` does not read it.

Each NAD joins **both**:

1. Access: **`access-marketing` only** (CoS lock). `devices.csv` has no Access column. Not a different default. Not round-robin. Not `hr` / `ceo` / `sourcecode` until Robert tags Access.
2. Location: that device's state/city NDG (`Location#All Locations#{State}#{site_id}`). Not the type-level `regional` / `branch` / `hq` / `dc` groups.

Shared secrets (never in git): `.env` `NAD_TACACS_SECRET` and `NAD_RADIUS_SECRET`. Both required whenever `nad_count>0`. One RADIUS secret for all NADs, same pattern as TACACS. NAD `authentication_network_protocol` is `RADIUS` (0.3.4 choices: `RADIUS` | `TACACS_PLUS`) so 802.1X can use the NAD. `tacacs_shared_secret` stays. CiscoDevNet/ise 0.3.4 field is `authentication_radius_shared_secret` (ERS `authenticationSettings.radiusSharedSecret`). `TF_VAR_nad_count=N` pushes the first N rows of `devices.csv`.

## Location NDG names

ISE already has `Location` / `All Locations`. This repo does not recreate that root. `#` is the path separator.

| Object | ISE path | Source |
| --- | --- | --- |
| Type | `Location#All Locations#regional` (also `branch`, `hq`, `dc`) | `location_ndgs.yaml`. `regional` = largest-city **type** only. |
| US state folder | `Location#All Locations#California` | Distinct `admin1` on US rows. Never named `regional`. |
| Non-US folder | `Location#All Locations#gb` | Distinct `cc` (no US state). |
| Site | `Location#All Locations#California#us-los-angeles` | One `sites.yaml` `id` under its state/country folder |

Leaf names must be ISE-legal (letters, digits, underscore, minus, dot; no `#`).

- **US state folder:** slug `admin1` — spaces → `_`. Identity when the name is already one word (`California`). Transforms: `District of Columbia` → `District_of_Columbia`, `New Hampshire` → `New_Hampshire`, `New Jersey` → `New_Jersey`, `New Mexico` → `New_Mexico`, `New York` → `New_York`, `North Carolina` → `North_Carolina`, `North Dakota` → `North_Dakota`, `Rhode Island` → `Rhode_Island`, `South Carolina` → `South_Carolina`, `South Dakota` → `South_Dakota`, `West Virginia` → `West_Virginia`. None of these is `regional`.
- **Non-US folder:** `cc` as-is (`gb`, `de`, …).
- **Site leaf:** `sites.yaml` `id` as-is (`us-los-angeles`). Already `[a-z0-9-]+`; no transform.

HQ/DC city tags are **not** invented.

## Wired 802.1X + MAB

Eleven groups and 110 lab MACs in Git. After merge, Robert pull / init / apply. This PR does **not** apply to ISE.

| Object | Source | 0.3.4 resource |
| --- | --- | --- |
| Endpoint identity groups | `endpoint_identity_groups.yaml` — Phones, AP, Printers, TVs, Badge_Readers, Cameras, UPS, Powerstrips, Linux, Windows, RFID_Readers. Drops Workstation / IP-Phone / Printer. | `ise_endpoint_identity_group` |
| Lab endpoints | `endpoints.csv` / `endpoints.yaml` — 10 unique lab MACs per group (110 total). Pattern `{IEEE MA-L OUI}:{generated last 3 octets}`. Generator: `scripts/generate_endpoints.py`. Not hardware. Git inventory only. | not `ise_endpoint` (apply does not read this file) |
| Allowed Protocols | `allowed_protocols.yaml` — `Wired_8021X` (EAP) and `Wired_MAB` (PAP/ASCII + Host Lookup) | `ise_allowed_protocols` (not `ise_allowed_protocols_tacacs`) |
| Authorization profiles | `authorization_profiles.yaml` — ACCESS_ACCEPT VLAN 10 data, 20 voice, 30 MAB | `ise_authorization_profile` (`access_type`, `vlan_name_id`, `vlan_tag_id`, `voice_domain_permission`). `dacl_name` exists in 0.3.4; omitted (no DACLs in Git). |
| Policy set | `network_access.yaml` — one Network Access set, not Device Admin | `ise_network_access_policy_set` |
| Authentication | `network_access_authc.csv` — Dot1X → Internal Users; MAB → Internal Endpoints `CONTINUE` | `ise_network_access_authentication_rule` + `ise_network_access_authentication_rule_update_ranks` |
| Authorization | `network_access_authz.csv` — first match: Phones → `Wired_Voice` (VLAN 20), Printers → `Wired_Printer` (VLAN 30), all other groups → `Wired_Data` (VLAN 10) | `ise_network_access_authorization_rule` (`profiles`) + `ise_network_access_authorization_rule_update_ranks` |

`endpoint_count` default is **150000**. Groups-only (no MAC rows): `TF_VAR_endpoint_count=0`. Cap with `TF_VAR_endpoint_count=N`. Lab `endpoints.csv` stays 110 in Git. No guest.

## Enterprise endpoint inventory (apply path)

NDO-200 lock (CoS 2026-09-01): **150,000** rows, **75,000** desks, each desk a **phone and a PC on the same switch port**. Not 300k. Terraform **must** read this file.

| Object | Source |
| --- | --- |
| Apply CSV | `endpoints_enterprise.csv` — exactly 150000 data rows. `ise_endpoint` (`name`, `mac`, `group_id`, `static_group_assignment`, `static_profile_assignment`). Rebuild: `python3 scripts/generate_enterprise_endpoints.py`. Check: `python3 scripts/generate_enterprise_endpoints.py --verify`. |
| Lab inventory | `endpoints.csv` / `endpoints.yaml` / `scripts/generate_endpoints.py` — still 110. Terraform does **not** `csvdecode` this file. |

Placement: 15,000 `devices.csv` access switches × 5 desks = 75,000 desks. Each desk uses one access port (`Gi1/0/1`–`Gi1/0/5` on that switch). The Phones row (IEEE MA-L `00:04:f2` Polycom) and the Windows/PC row (`10:e7:c6` Hewlett Packard) share that port, site, and switch. Columns `desk`, `switch`, `port`, `site` are on every row so the pairing is visible in Excel.

**Default apply is 150k.** pan1 apply is `TF_VAR_endpoint_count` / default **150000** against `endpoints_enterprise.csv`. Do not apply the lab 110 with the 150k (Small PAN). No 150k YAML (GitHub size). `nac-validate` still runs on the existing YAML set (lab 110) only.

Lab MACs use locked IEEE MA-L OUIs from https://standards-oui.ieee.org/oui/oui.txt plus generated last 3 octets (SHA-256 lab suffixes, unique across 110). Not `02:00:GG`. Not `00:00:01`–`00:00:0A`. CSV cites `oui` and IEEE `organization`. Documented as lab. Not copied from hardware.

`ise_network_access_policy_set.service_name` binds **one** Allowed Protocols name. This repo binds `Wired_8021X`. Host Lookup is also enabled on that list so the MAB authentication rule in the same set can fire. `Wired_MAB` stays the PAP/ASCII specialist.

TACACS device-admin stays (`*_cs` / `*_shell`, Device Admin policy set, GUI canary `"-target=ise_tacacs_command_set.test"`).

## Internal Users (`users.csv`)

Lab Internal Users in Git. After merge, Robert pull / init / apply. This PR does **not** apply to ISE. Secrets never go in Git.

| Object | Source | 0.3.4 resource / field |
| --- | --- | --- |
| User identity groups | `tacacs_authz.csv` — T1, T2, T3, T4, vendor, contractor, `auditor-internal`, `auditor-external` (hyphens stay) | `ise_user_identity_group` |
| Lab Internal Users | `users.csv` / `users.yaml` — 8 lab accounts, one per TACACS group. Generator: `scripts/generate_users.py`. Not 150k. | `ise_internal_user` |

CiscoDevNet/ise **0.3.4** resource name is **`ise_internal_user`** (not `ise_user`). Schema fields this repo sets:

| Field | Source |
| --- | --- |
| `name` | `users.csv` `username` |
| `password` | env only: `USER_PASSWORD_DEFAULT` → `TF_VAR_user_password` |
| `enable_password` | env: `USER_ENABLE_PASSWORD_DEFAULT` → `TF_VAR_user_enable_password` (empty reuses login) |
| `change_password` | `false` (lab first login must work; provider default is `true`) |
| `enabled` | CSV `enabled` |
| `first_name` / `last_name` / `email` / `description` | CSV |
| `identity_groups` | comma-separated **identity group IDs** from `ise_user_identity_group.this[group].id` |
| `password_id_store` | `Internal Users` |
| `password_never_expires` | `true` (lab; ISE 3.2+) |

Not set: `account_name_alias`, `custom_attributes`.

CSV columns (no secret column): `username`, `identity_group`, `first_name`, `last_name`, `email`, `enabled`, `description`. `identity_group` must match a live TACACS identity group. Multiple groups can be comma-separated later; the lab CSV has one each.

`user_count` default is **8** (house style: lab CSV length, same idea as `nad_count=15000` / `endpoint_count=150000`). Skip user rows: `TF_VAR_user_count=0`. Empty `USER_PASSWORD_DEFAULT` with `user_count>0` fails with a clear error. Do not generate 150k users.

ERS creates **one user per POST** (`POST /ers/config/internaluser`). ISE Internal User store **max is 300,000** ([Performance and Scalability Guide](https://www.cisco.com/c/en/us/td/docs/security/ise/performance_and_scalability/b_ise_perf_and_scale.html)). This PR is the lab CSV only. Schema: [ise_internal_user 0.3.4](https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/internal_user). ERS: [Create User](https://developer.cisco.com/docs/identity-services-engine/latest/create-user/).

## Provider

This repo uses **CiscoDevNet/ise** (current public Cisco ISE Terraform provider, tested with ISE 3.5). It is the current replacement for the older `CiscoISE/ciscoise` beta.

Password and username come from the environment / `.env`. Nothing in git has the lab password.

## What the provider cannot fully express

These still produce a valid `terraform init`. Some objects are incomplete because the CSVs do not contain the data:

| Object | In Git | On apply |
| --- | --- | --- |
| TACACS command sets | `command_sets.yaml` — YAML `name:` is the ISE name (`T1_cs`–`T3_cs`, `vendor_cs`, `contractor_cs`, `auditor_internal_cs`, `auditor_external_cs`). T4_cs empty with `permit_unmatched=true`. CSV keys stay `T1`. Arguments are literals + `*` (no PCRE). | `ise_tacacs_command_set` `name` is `local.ise_tacacs_command_set_name` (`T1_cs`). Canary `.test` POSTs `test_cs`. `permit_unmatched=false` except T4. |
| TACACS shell profiles | `shell_profiles.yaml` — YAML `name:` is the ISE name (`T1_shell`, `T2_shell`, …). `session_attributes` `type=MANDATORY` `name=priv-lvl` `value=1` for T1 and `auditor_*`; `15` for T2/T3/T4/vendor/contractor. CSV keys stay `T1`. | `ise_tacacs_profile` name is `local.ise_tacacs_shell_profile_name` (`T1_shell`, not `T1`). ISE ERS shares one name namespace with command sets. Authz `profile` uses `.name`. Names cannot contain hyphens. |
| `time_bound=yes` | Flag only (vendor, auditor-external identity) | Not attached. Hours were not in the CSV. The provider *can* create a time-and-date condition if hours are added later. |
| Identity groups | Names (`T1`–`T4`, vendor, contractor, auditor-*) | Groups from `tacacs_authz.csv`. Lab Internal Users from `users.csv` join via `ise_internal_user.identity_groups` (group IDs). Default `user_count=8`. `TF_VAR_user_count=0` skips user rows. Secrets in `.env` only. |
| Identity store | CSV says `ISE Internal Users` | Mapped to ISE's built-in store name `Internal Users`. Not Active Directory. |
| NAD → NDG | Access locked to `access-marketing`. Location is `Location#All Locations#{State}#{site_id}` | Default `nad_count=15000` joins Access **and** the state/city Location. Protocol is `RADIUS`. `TF_VAR_nad_count=0` is policy-only. |
| Endpoint identity groups | `endpoint_identity_groups.yaml` — Phones, AP, Printers, TVs, Badge_Readers, Cameras, UPS, Powerstrips, Linux, Windows, RFID_Readers | 11 groups. Default `endpoint_count=150000` pushes `endpoints_enterprise.csv`. Lab `endpoints.csv` (110) is inventory only. `TF_VAR_endpoint_count=0` is groups-only. |
| Network Access identity | CSV says `ISE Internal Users` / `ISE Internal Endpoints` | Mapped to `Internal Users` / `Internal Endpoints`. Not Active Directory. |

See [PLAN.md](PLAN.md) for the device-admin design and this 802.1X/MAB phase.
