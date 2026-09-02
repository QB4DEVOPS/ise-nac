# Site list sources

`sites.yaml` has exactly 400 unique real cities. Names were not invented.

## United States (300 cities)

U.S. Census Bureau, Population Division.

Annual Estimates of the Resident Population for Incorporated Places of 20,000
or More, Ranked by July 1, 2025 Population: April 1, 2020 to July 1, 2025
(file `SUB-IP-EST2025-ANNRNK`).

- Table page: https://www.census.gov/data/tables/time-series/demo/popest/2020s-total-cities-and-towns.html
- Spreadsheet: https://www2.census.gov/programs-surveys/popest/tables/2020-2025/cities/totals/SUB-IP-EST2025-ANNRNK.xlsx

The 50 `type: regional` rows are the most populous place in each of the 50 U.S.
states in that ranking (Honolulu is listed by Census as Urban Honolulu CDP).
The other U.S. rows are the next most populous places from the same file,
including Washington, D.C. as a branch (D.C. is not a state, so it is not
regional).

Census legal names are shortened to the common city name where the legal name
is a consolidated government, for example Nashville-Davidson metropolitan
government (balance) → Nashville. The place is the same Census row.

## Worldwide remainder (100 cities)

GeoNames gazetteer dump `cities15000` (populated places with population
greater than 15,000, or capitals), Creative Commons Attribution 4.0.

- Download: https://download.geonames.org/export/dump/cities15000.zip
- Admin-1 names: https://download.geonames.org/export/dump/admin1CodesASCII.txt
- Project: https://www.geonames.org/

Non-U.S. rows only. Each row is the most populous GeoNames city in its
country; the 100 countries with the largest such cities are included.

## Not in this file

No HQ, DC (data-center), or IAP rows. No coordinates. `type` is only
`regional` or `branch`.

## Excel copies (generated)

`sites.csv` is generated from `sites.yaml` (same 400 rows: id,city,admin1,cc,type). YAML stays the policy original.

`ndgs.csv` is the four device-admin access groups from PLAN.md (not a site tree):
access-marketing (T1+), access-hr (T2+), access-ceo (T3+), access-sourcecode (T4).
CoS lock: until Robert tags Access, every NAD is assigned `access-marketing`
only. Not a different default. Not round-robin.

Location NDGs: type-level groups live in `location_ndgs.yaml`. **`regional`
is only the largest-city site type**, sibling of `branch` / placeholders
`hq`/`dc`. Do not name any US state folder `regional`. US folder = slugged
`admin1` (`California`, `New_York`). Non-US folder = `cc`. Site ISE path
is `Location#All Locations#{State}#{site_id}`. Site ids are already
ISE-legal (`[a-z0-9-]+`); no rename.

`tacacs_authc.csv` is one TACACS authentication rule in ISE push order. No identity
store was given, so the lab default is ISE Internal Users (protocol TACACS). Do not
assume Active Directory.

`network_access_authc.csv` / `network_access_authz.csv` are wired 802.1X + MAB
policy rules in ISE push order (first match wins), same style as the TACACS CSVs.
YAML originals: `endpoint_identity_groups.yaml`, `endpoints.yaml`,
`allowed_protocols.yaml`, `authorization_profiles.yaml`, `network_access.yaml`.
Eleven groups (Phones, AP, Printers, TVs, Badge_Readers, Cameras, UPS,
Powerstrips, Linux, Windows, RFID_Readers). `endpoints.csv` is 110 lab
MACs (10 per group) from `scripts/generate_endpoints.py`: locked IEEE
MA-L OUI + generated last 3 octets. Source:
https://standards-oui.ieee.org/oui/oui.txt. CSV cites `oui` and IEEE
`organization`. Not hardware. No guest. No 15k dump.

`users.csv` / `users.yaml` are lab Internal Users from
`scripts/generate_users.py`. Eight accounts, one per TACACS identity
group (T1, T2, T3, T4, vendor, contractor, auditor-internal,
auditor-external). Hyphens stay. No password column. Login/enable
secrets stay in `.env` (`USER_PASSWORD_DEFAULT`,
`USER_ENABLE_PASSWORD_DEFAULT`). `user_count` default 8. Not 150k.
ISE Internal User store max is 300,000. ERS POSTs one user per create
(`ise_internal_user` 0.3.4).

Locked IEEE MA-L OUIs (https://standards-oui.ieee.org/oui/oui.txt), verified
against the (hex) assignment — do not invent others:

| Group | OUI | IEEE organization |
| --- | --- | --- |
| Phones | 00:04:F2 | Polycom |
| AP | 9C:E3:30 | Cisco Meraki |
| Printers | 9C:7B:EF | Hewlett Packard |
| TVs | 64:1B:2F | Samsung Electronics Co.,Ltd |
| Badge_Readers | 00:30:8E | Crossmatch Technologies/HID Global |
| Cameras | 00:40:8C | Axis Communications AB |
| UPS | 00:C0:B7 | AMERICAN POWER CONVERSION CORP |
| Powerstrips | 00:0D:5D | Raritan Computer, Inc |
| Linux | 00:C0:4F | Dell Inc. |
| Windows | 10:E7:C6 | Hewlett Packard |
| RFID_Readers | 00:16:25 | Impinj, Inc. |

Last 3 octets are hashed lab suffixes, unique across 110, not `00:00:01`–
`00:00:0A`, not copied from a NIC. Drop the `02:00:GG` pattern.

`endpoints_enterprise.csv` is the NDO-200 Git-only inventory: **150,000**
rows, **75,000** desks, phone + PC on the same switch port. Generator:
`scripts/generate_enterprise_endpoints.py`. Not hardware. Same IEEE MA-L
OUIs for Phones (`00:04:F2` Polycom) and Windows (`10:E7:C6` Hewlett
Packard). Placement is 5 desks per `devices.csv` switch (`Gi1/0/1`–
`Gi1/0/5`). Terraform does not read this file. pan1 apply stays the 110
lab MACs (`endpoint_count` default 110) until Robert says otherwise. No
150k YAML.

`tacacs_authz.csv` is TACACS authorization rules in ISE push order (first match
wins), from PLAN.md only: T1–T4 against the NDG min-tier table, vendor (time-bound,
NDG-scoped), contractor, auditor-internal (all four NDGs, read-only),
auditor-external (time-bound, read-only). Identity groups keep hyphens.
`command_set` CSV keys stay T1 (ISE-legal tokens, no hyphens). Command-set
ISE names and `command_sets.yaml` `name:` are `{key}_cs` (`T1_cs`,
`vendor_cs`, …). The GUI canary resource address stays
`ise_tacacs_command_set.test` and POSTs ISE name `test_cs`. Shell-profile
CSV keys stay T1; `shell_profiles.yaml` `name:` and the ISE POST name are
`{key}_shell` (`T1_shell`, `vendor_shell`, …) because ISE ERS shares one
name namespace — every TACACS object is suffixed. Both named `T1` returns
HTTP 400.
IOS-XE command contents live in `command_sets.yaml` (Terraform
`ise_tacacs_command_set` commands blocks). ISE ERS arguments are literal
tokens plus optional `*` (not PCRE). T4 may permit unmatched; every other
set lists real commands and denies unmatched. Shell privilege is
`session_attributes` in `shell_profiles.yaml` (`type=MANDATORY`,
`name=priv-lvl`). Country is not a condition.

No admin accounts or lab management addresses in Git. Internal User
login/enable secrets are `.env` only (`USER_PASSWORD_DEFAULT`).

## Access switches (`devices.csv`)

`devices.csv` is TARS-owned access-layer inventory. Generated by
`scripts/generate_devices.py` from `sites.csv` (not hand-typed). Rebuild:
`python3 scripts/generate_devices.py`.

Locked math: 50 regional sites × 48 switches = 2,400; 350 branch sites ×
36 switches = 12,600; total 15,000. Role is `sw`, OS is IOS-XE. Last octet
`{nn}` is 1–254; 48 and 36 both fit. No HQ/DC types in the sites file, so
none were added.

Hostname is `{cc}{site}-sw-{nn}` with a 3–4 character site token derived from
the city name. `site_code` is the `sites.csv` id (real city row). Management
loopback is `10.{country_id}.{site_id}.{nn}/32`. US has 300 sites, so it uses
two `/16` blocks (`country_id` 1 and 2); other countries use one `/16`.
`site_id` is 1–254 inside each block.

Access switches only. No core, distribution, WAN, WLC, firewalls, or ISE
nodes. No passwords or 192.168.1.90.

`nac.yaml` is generated from the CSVs by `scripts/generate_nac.py` (ISE-as-code feed; CSV stays what Excel opens).
