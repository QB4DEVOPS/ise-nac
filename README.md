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
nac-validate nac.yaml sites.yaml -s .schema.yaml -r .rules
```

That is Cisco Network as Code [`nac-validate`](https://github.com/netascode/nac-validate). `.schema.yaml` checks the shape of `nac.yaml` / `sites.yaml`. `.rules/` also reads `tacacs_authz.csv`, `command_sets.yaml`, and Terraform (`local.ise_tacacs_name` in `locals.tf`, commands in `main.tf`) — the names and commands apply POSTs to ISE, not only `nac.yaml`:

1. TACACS **command-set** and **profile** names may only use letters, digits, underscore, and space. Hyphens fail (`auditor-internal` / `auditor-external`). NDG hyphens (`access-marketing`) stay.
2. Non-T4 command sets must list real IOS commands with `permit_unmatched = false`. T4 may be empty with `permit_unmatched = true`. Empty sets with `permit_unmatched = false` are invalid (HTTP 400).
3. **Rule 103 FAILS** (non-zero exit) if command `arguments` contain regex metacharacters (`(`, `)`, `?`, `|`, `.`, etc.). Plain words and `*` only. Missing `command_sets.yaml` also fails (closed). PCRE such as `ver(sion)?.*` 400s on ISE.
4. Shell profiles POST `session_attributes` (`type=MANDATORY`, `name=priv-lvl`, `value=1` or `15`). Empty profiles 400 on ISE 3.5.

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

That address is `ise_tacacs_command_set.test`. ISE name is exactly `test`: one command, `show` / `version` / `PERMIT`, `permit_unmatched=false`. No regex. If this 400s, Device Admin / TACACS may not be licensed yet.

If you already ran apply once, pull this folder first, then apply again:

```
git pull
. .\load-env.ps1
terraform apply
```

## First apply (no 6,250 NADs)

Default NAD count is **0**. First apply creates policy objects only:

- Four NDGs from `ndgs.csv`: `access-marketing`, `access-hr`, `access-ceo`, `access-sourcecode`
- TACACS authentication sequence from `tacacs_authc.csv`
- TACACS authorization rules from `tacacs_authz.csv` in ISE push order (first match wins)

This does **not** deploy ESXi, an OVA, or C:\Marco paths.

## Tiny NAD sample later

To push two sample switches only (not 6,250):

```
. .\load-env.ps1
terraform apply -var "nad_count=2"
```

## Provider

This repo uses **CiscoDevNet/ise** (current public Cisco ISE Terraform provider, tested with ISE 3.5). It is the current replacement for the older `CiscoISE/ciscoise` beta.

Password and username come from the environment / `.env`. Nothing in git has the lab password.

## What the provider cannot fully express

These still produce a valid `terraform init`. Some objects are incomplete because the CSVs do not contain the data:

| Object | In Git | On apply |
| --- | --- | --- |
| TACACS command sets | `command_sets.yaml` — real IOS-XE commands (`T1`–`T3`, vendor, contractor, `auditor_internal`, `auditor_external`). T4 empty with `permit_unmatched=true`. CSV hyphens map to underscores. Arguments are literals + `*` (no PCRE). | `ise_tacacs_command_set` with `commands` (`grant=PERMIT`, command, arguments). `permit_unmatched=false` except T4. |
| TACACS shell profiles | `shell_profiles.yaml` — `session_attributes` `type=MANDATORY` `name=priv-lvl` `value=1` for T1 and `auditor_*`; `15` for T2/T3/T4/vendor/contractor | `ise_tacacs_profile` session_attributes per CiscoDevNet/ise 0.3.4. Names cannot contain hyphens. |
| `time_bound=yes` | Flag only (vendor, auditor-external identity) | Not attached. Hours were not in the CSV. The provider *can* create a time-and-date condition if hours are added later. |
| Identity groups | Names (`T1`–`T4`, vendor, contractor, auditor-*) | Empty groups. No users and no passwords. |
| Identity store | CSV says `ISE Internal Users` | Mapped to ISE's built-in store name `Internal Users`. Not Active Directory. |
| NAD → NDG | `devices.csv` has no NDG column | Sample NADs (if `nad_count=2`) go in `access-marketing`. |

See [PLAN.md](PLAN.md) for the device-admin design.
