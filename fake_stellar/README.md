# Stellar Express Courier — showcase companions (demo only)

These files are a **demo-only** inventory pack for
[`fake_ise_system_full.yaml`](../fake_ise_system_full.yaml). They are **not**
consumed by Terraform. Do not `terraform apply`. Do not contact a live ISE.

The light demo [`fake_ise_system.yaml`](../fake_ise_system.yaml) stays as-is.

## Hard naming rule

Every inventory file in this folder uses the `stellar_express_` prefix.

| This pack | Never use (production apply names) |
| --- | --- |
| `stellar_express_sites_sample.csv` | `sites.csv` |
| `stellar_express_devices_sample.csv` | `devices.csv` |
| `stellar_express_endpoints_sample.csv` | `endpoints.csv`, `endpoints_enterprise.csv` |
| `stellar_express_location_ndgs_sample.csv` | `location_ndgs.yaml` as an apply feed |

Do not overwrite or shadow the production apply files at the repo root.

## What is committed

Generator + **sample** CSVs. Scale counts are **not CoS-locked**. Until Crew
confirms a final volume, this PR does **not** include a 150k-row endpoints
CSV (GitHub also cannot host that as a literal YAML).

| File | Rows (data) | Role |
| --- | ---: | --- |
| `stellar_express_sites_sample.csv` | 9 | YAML campus subset (Houston HQ, Dallas DC, …) |
| `stellar_express_devices_sample.csv` | 29 | Access NADs for those 9 sites |
| `stellar_express_endpoints_sample.csv` | 110 | 10 MACs × 11 identity groups |
| `stellar_express_location_ndgs_sample.csv` | 21 | Type + state/cc + site folders for the 9 |

Rebuild samples:

```
python3 fake_stellar/scripts/generate_stellar_inventory.py
python3 fake_stellar/scripts/generate_stellar_inventory.py --verify
```

## Production-ish generation (local only)

`--full` can emit production-ish counts. Those filenames are gitignored until
CoS locks scale. They still use the `stellar_express_` prefix.

```
python3 fake_stellar/scripts/generate_stellar_inventory.py --full
```

| File (gitignored) | Target rows | Expected size (approx.) |
| --- | ---: | --- |
| `stellar_express_sites.csv` | 400 | ~20 KB |
| `stellar_express_devices.csv` | 15,000 | ~1.3 MB |
| `stellar_express_endpoints.csv` | 150,000 | ~19 MB |
| `stellar_express_location_ndgs.csv` | ~550 | ~40 KB |

150k endpoints at ~19 MB is under GitHub’s 100 MB file limit, but it is **not**
in this PR. If CoS later wants the giant file published, attach a **GitHub
Release zip** — do not rename it to `endpoints_enterprise.csv`.

`--full` reads public city names from repo-root `sites.csv` (Census/GeoNames
catalog already in this repo) and does **not** write that file. Houston is
tagged `hq`, Dallas `dc`; a few showcase types follow the YAML (London
regional; Portland OR and Milwaukee branch).

Device management IPs are RFC 5737 only. A /24 cannot hold 15k unique
addresses, so `--full` uses a **site-local** TEST-NET overlay (unique per
site, reused across sites). Samples in git use unique documentation IPs.

## Safety

- No passwords, tokens, keys, or certificates
- RFC 5737 documentation IPs only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- Uppercase colon-hex synthetic MACs (IEEE MA-L OUI + hashed NIC suffix)
- Emails in the YAML shell are `@example.com` only
- Not hardware. Not copied from a NIC. No `02:00:GG`. No `00:00:01`–`00:00:0A`

## Validate (no production `.rules`)

```
python3 -c "import yaml; yaml.safe_load(open('fake_ise_system_full.yaml'))"
# Schema only. nac-validate loads cwd .rules by default — that is the
# production apply lock and must not be used on this demo file.
nac-validate fake_ise_system_full.yaml -s .schema.yaml -r /tmp/empty-nac-rules
python3 fake_stellar/scripts/generate_stellar_inventory.py --verify
```

Create `/tmp/empty-nac-rules` first (empty directory). Do **not** pass
`-r .rules`.
