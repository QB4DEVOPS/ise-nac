# ise-nac

ISE device-admin Network as Code.

Robert: use PowerShell in this folder. The command is `terraform` (not `tf`).

## One-time setup

1. Install Terraform from https://developer.hashicorp.com/terraform/install
2. Open PowerShell in this folder.
3. Copy the example env file and put the lab password in `.env` (this file is not in git):

```
copy .env.example .env
notepad .env
```

Change `ISE_PASSWORD=changeme` to the real lab password. Save. Close Notepad.

On ISE, turn on **ERS** and **Open API** (Administration → System → Settings → API Settings). Device Admin / TACACS must be licensed.

## Validate YAML before apply

Run this in PowerShell **before** `terraform apply`. Python 3.10+ is required ([install Python](https://www.python.org/downloads/) if `pip` is missing).

```
pip install nac-validate
nac-validate nac.yaml sites.yaml location_ndgs.yaml -s .schema.yaml -r .rules
```

That is Cisco Network as Code [`nac-validate`](https://github.com/netascode/nac-validate). `.schema.yaml` checks the shape of `nac.yaml` / `sites.yaml` / `location_ndgs.yaml`. `.rules/` also reads `tacacs_authz.csv`, `command_sets.yaml`, and Terraform (`local.ise_tacacs_command_set_name` / `local.ise_tacacs_shell_profile_name` in `locals.tf`, commands in `main.tf`) — the names and commands apply POSTs to ISE, not only `nac.yaml`:

1. TACACS **command-set** and **profile** names may only use letters, digits, underscore, and space. Hyphens fail (`auditor-internal` / `auditor-external`). NDG hyphens (`access-marketing`) stay.
2. Non-T4 command sets must list real IOS commands with `permit_unmatched = false`. T4 may be empty with `permit_unmatched = true`. Empty sets with `permit_unmatched = false` are invalid (HTTP 400).
3. **Rule 103 FAILS** (non-zero exit) if command `arguments` contain regex metacharacters (`(`, `)`, `?`, `|`, `.`, etc.). Plain words and `*` only. Missing `command_sets.yaml` also fails (closed). PCRE such as `ver(sion)?.*` 400s on ISE.
4. Shell profiles POST `session_attributes` (`type=MANDATORY`, `name=priv-lvl`, `value=1` or `15`). Empty profiles 400 on ISE 3.5.
5. **Rule 105 FAILS** if any string is duplicated in the **combined** set of all command-set ISE names and all profile ISE names (one ERS namespace). Every TACACS object is suffixed (underscore only). Command sets: `T1_cs` `T2_cs` `T3_cs` `T4_cs` `vendor_cs` `contractor_cs` `auditor_internal_cs` `auditor_external_cs` `test_cs`. Profiles: `T1_shell` `T2_shell` `T3_shell` `T4_shell` `vendor_shell` `contractor_shell` `auditor_internal_shell` `auditor_external_shell`. No profile named `test_cs`. CSV keys stay `T1`. Identity groups, NDGs, and authz rule names are unchanged.
6. **Rule 106 FAILS** if a user identity group name equals any string in that TACACS bag. Live groups (`T1`, `auditor-internal`) stay; `T1` does not collide with `T1_cs` / `T1_shell`. Suffix an identity group only when it would reuse a command-set or profile ISE name.

If `nac-validate` prints errors, do not apply. Exit 0 means schema and these rules passed. It still does not talk to ISE.

Optional git hook (same check on commit):

```
pip install pre-commit
pre-commit install
```

## Commands

Validate YAML first (`nac-validate` above). Then Terraform.

`terraform init` only downloads the Cisco ISE plugin. The PAN does **not** need to be reachable.

`terraform plan` and `terraform apply` talk to the PAN at `ISE_HOST` (`192.168.1.90`). The PAN must be up.

Paste this in PowerShell (loads `.env`, then the three terraform commands):

```
. .\load-env.ps1
terraform init
terraform plan
terraform apply
```

If PowerShell says scripts are disabled, paste this first:

```
Set-ExecutionPolicy -Scope Process Bypass
```

Then paste the block above.

## GUI canary (do not click ISE)

TARS owns the NAC. Terraform creates the GUI test. Robert does not click ISE to make it.

```
. .\load-env.ps1
terraform apply -target=ise_tacacs_command_set.test
```

That address is `ise_tacacs_command_set.test`. ISE name is `test_cs`: one command, `show` / `version` / `PERMIT`, `permit_unmatched=false`. No regex. If this 400s, Device Admin / TACACS may not be licensed yet.

If you already ran apply once, pull this folder first, then apply again:

```
git pull
. .\load-env.ps1
terraform apply
```

## First apply (no 6,250 NADs)

Default NAD count is **0**. A normal apply still creates policy objects **and** the Location NDG tree (151 regions + 400 sites + 4 type-level). It does **not** create NADs.

- Four Access NDGs from `ndgs.csv`: `access-marketing`, `access-hr`, `access-ceo`, `access-sourcecode`
- Four type-level Location NDGs under ISE All Locations: `regional`, `branch` (from `sites.yaml` types), plus placeholders `hq` and `dc` with description `no sites tagged yet`. NADs do **not** join these type groups.
- One region Location NDG per US state (`admin1`) and per non-US country (`cc`). See [Location NDG names](#location-ndg-names).
- One site Location NDG per `sites.yaml` row, nested under its region. Types stay `regional` / `branch`. No HQ/DC city tags.
- TACACS authentication sequence from `tacacs_authc.csv`
- TACACS authorization rules from `tacacs_authz.csv` in ISE push order (first match wins)

This does **not** deploy ESXi, an OVA, or C:\Marco paths.

**Warning:** applying **6,250 NADs + 555 Location NDGs** (151 regions + 400 sites + 4 types) on one PAN will take a long time. Default `nad_count=0` still pushes the Location tree. Do not apply from an agent.

## NAD inventory (devices.csv)

Default `nad_count` stays **0**. The intended inventory is every row in `devices.csv` (**6,250** access switches), not the old sample of 8. `sample_nads.csv` can stay as a tiny optional reference slice; `nad_count` does not read it.

Each NAD joins **both**:

1. Access: **`access-marketing` only** (locked). `devices.csv` has no Access column. Do not round-robin and do not invent `hr` / `ceo` / `sourcecode` tags until Robert tags Access.
2. Location: that device's nested site NDG (`Location#All Locations#{region}#{site_id}`). Not the type-level `regional` / `branch` / `hq` / `dc` groups.

Put the TACACS shared secret in `.env` as `NAD_TACACS_SECRET` (never in git). Full push:

```
. .\load-env.ps1
$env:TF_VAR_nad_count = "6250"
terraform apply
```

Same thing without PowerShell env assignment: `TF_VAR_nad_count=6250` in the environment. Required: `TF_VAR_nad_tacacs_secret` (loaded from `NAD_TACACS_SECRET`). There is no secret default in git. `TF_VAR_nad_count=N` pushes the first N rows of `devices.csv`.

## Location NDG names

ISE already has `Location` / `All Locations`. This repo does not recreate that root. `#` is the path separator.

| Object | ISE path | Source |
| --- | --- | --- |
| Type | `Location#All Locations#regional` (also `branch`, `hq`, `dc`) | `location_ndgs.yaml` |
| US region | `Location#All Locations#California` | Distinct `admin1` on `cc: us` rows |
| Non-US region | `Location#All Locations#gb` | Distinct `cc` on non-US rows |
| Site | `Location#All Locations#California#us-los-angeles` | One `sites.yaml` `id` under its region |

Leaf names must be ISE-legal (letters, digits, underscore, minus, dot; no `#`). Mapping:

- **US state:** slug `admin1` — spaces and punctuation become `_`. Identity when the state is already one word (`California`). Transforms: `District of Columbia` → `District_of_Columbia`, `New Hampshire` → `New_Hampshire`, `New Jersey` → `New_Jersey`, `New Mexico` → `New_Mexico`, `New York` → `New_York`, `North Carolina` → `North_Carolina`, `North Dakota` → `North_Dakota`, `Rhode Island` → `Rhode_Island`, `South Carolina` → `South_Carolina`, `South Dakota` → `South_Dakota`, `West Virginia` → `West_Virginia`.
- **Non-US region:** `cc` as-is (`gb`, `de`, …).
- **Site leaf:** `sites.yaml` `id` as-is (`us-los-angeles`). Already `[a-z0-9-]+`; no transform.

Sites are **not** flattened under All Locations. HQ/DC city tags are **not** invented.

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
| Identity groups | Names (`T1`–`T4`, vendor, contractor, auditor-*) | Empty groups. No users and no passwords. |
| Identity store | CSV says `ISE Internal Users` | Mapped to ISE's built-in store name `Internal Users`. Not Active Directory. |
| NAD → NDG | Access locked to `access-marketing`. Location is the nested site NDG from `sites.yaml` | `TF_VAR_nad_count=6250` joins Access **and** site Location. Default count is 0. |

See [PLAN.md](PLAN.md) for the device-admin design.
