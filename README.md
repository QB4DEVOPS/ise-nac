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

## Commands

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

These still produce a valid `terraform init`. They are incomplete because the CSVs do not contain the data:

| Object | In Git | On apply |
| --- | --- | --- |
| TACACS command sets | CSV names (`T1`–`T4`, vendor, contractor, auditor-*) | ISE names with hyphen → underscore (`auditor_external`). No IOS commands. `permit_unmatched = true` so an empty set is valid. |
| TACACS shell profiles | CSV names | Same hyphen → underscore map. ISE 3.5 rejects empty profiles, so each profile has a privilege-1 stub (`priv-lvl=1`). Not a full shell. |
| `time_bound=yes` | Flag only (vendor, auditor-external) | Not attached. Hours were not in the CSV. The provider *can* create a time-and-date condition if hours are added later. |
| Identity groups | Names (`T1`–`T4`, vendor, contractor, auditor-*) | Empty groups. No users and no passwords. |
| Identity store | CSV says `ISE Internal Users` | Mapped to ISE's built-in store name `Internal Users`. Not Active Directory. |
| NAD → NDG | `devices.csv` has no NDG column | Sample NADs (if `nad_count=2`) go in `access-marketing`. |

See [PLAN.md](PLAN.md) for the device-admin design.
