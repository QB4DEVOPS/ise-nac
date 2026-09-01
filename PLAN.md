# ISE NaC — Device Administration

Rebuild ISE from Git. Clone is the source of truth. If you have to click, we failed.

## Goal

Customer-ready **device administration** on Cisco ISE, expressed as Network as Code.

- Story scale: ~100k users, 400+ sites, 15k NADs, multinational
- Product: TACACS device admin **plus** wired 802.1X / MAB (this phase)
- RADIUS on NADs so 802.1X can use the switch; TACACS shared secret stays
- Guest / unknown / wireless stay **out**
- Ignore internode latency
- One Palo Alto as a choke. Dual-home is a later commit, after Git rebuild works
- CML is optional. Terraform is the truck. YAML is the policy

## v1 in Git

| Artifact | What it is |
| --- | --- |
| NDG tree | Access groups plus Location: type-level (`regional` = largest-city type only, `branch`, placeholders `hq`/`dc`) and one state/city path `Location#All Locations#{State}#{site_id}` |
| Command sets | T1–T4 ladder. Vendor (time-bound, NDG-scoped). Contractor. Auditor internal (all NADs, read-only). Auditor external (time-bound, read-only) |
| Generator | Stamps 15k NAD records off the site list (CSV) |
| ISE deploy | PAN / MnT / PSN split. Four regional PSNs in the story, two in the lab |
| Accounting | SOX = accounting + separation of duties (the T1–T4 ladder). PII lives in MnT and TACACS logs; in-region in the story |

Country stays **off** command sets and policy sets. It belongs on hostname, loopback, and log residency, not on every rule.

## Site names

Pattern: `{cc}{site}` lowercase, no spaces.

- `{cc}` ISO 3166-1 alpha-2 (`us`, `de`, `in`, `br`)
- `{site}` 3–4 char location (`nyc`, `fra`, `blr`, `spo`)
- Hostname: `{cc}{site}-{role}-{nn}` e.g. `usnyc-sw-01`, `defra-wlc-01`

400+ sites live in `sites.yaml`. Location NDG is `Location#All Locations#{State}#{site_id}`. Excel copies: `sites.csv`, `ndgs.csv`, `tacacs_authc.csv`, `tacacs_authz.csv`, `devices.csv`.

## Management loopbacks

One loopback per NAD. Plan is 15k addresses, ~37 NADs per site at 400 sites. Give each site a `/24`.

- Block: `10.0.0.0/8`
- Per country: `10.{cc_id}.0.0/16` (`cc_id` from `sites.yaml`, 1–254)
- Per site: `10.{cc_id}.{site_id}.0/24` (`site_id` 1–254 per country)
- Device: `10.{cc_id}.{site_id}.{nn}/32` (`nn` 1–254)

Example: `usnyc-sw-01` → `10.1.1.1/32`

No overlap with underlay/P2P. Loopbacks are management only.

## NDG — Access groups plus Location tree

Four Access groups. That is the access list.

| NDG | Who may administer those NADs |
| --- | --- |
| `access-marketing` | T1+ |
| `access-hr` | T2+ |
| `access-ceo` | T3+ |
| `access-sourcecode` | T4 |

CoS lock: until Robert tags Access, every NAD joins **`access-marketing` only**. Not a different default. Not round-robin. Do not invent hr/ceo/sourcecode membership.

Vendor is time-bound and scoped to one of these. Auditors are read-only across all four.

Location NDGs sit under ISE **All Locations**. Type-level groups stay as type groups. **`regional` is only the largest-city site type** — never a US state folder. Each US `admin1` is a Location folder; each site sits under that folder.

| Location NDG | ISE path | Source |
| --- | --- | --- |
| `regional` / `branch` | `Location#All Locations#{type}` | Site **type** only (`regional` = largest-city type) |
| `hq` / `dc` | `Location#All Locations#{type}` | Placeholder. No sites tagged yet |
| US state folder | `Location#All Locations#California` | Distinct `admin1` (never named `regional`) |
| Non-US folder | `Location#All Locations#gb` | Distinct `cc` |
| Site | `Location#All Locations#California#us-los-angeles` | One `sites.yaml` `id` under its state/country |

NADs join the **state/city** Location NDG, not the type-level parent. Do not reclassify cities into HQ/DC without evidence.

## Out of v1 (still)

- Wireless 802.1X, guest, unknown
- Dual PAN
- Per-nation ISE clusters / MnT split
- Standing up gear on the LAN until Robert clears it
- MAC endpoint lists at story scale (300k MACs). Lab is 110 generated MACs. Do not dump 15k.

## Wired 802.1X + MAB (this phase)

Eleven groups and 110 lab MACs in Git. After merge, Robert pull / init / apply. Do not apply from an agent.

- Endpoint identity groups: Phones, AP, Printers, TVs, Badge_Readers, Cameras, UPS, Powerstrips, Linux, Windows, RFID_Readers. Drops Workstation / IP-Phone / Printer. No guest.
- 10 unique lab MACs per group (110 total). IEEE MA-L OUI + generated last 3 octets. Generator, not hardware. `endpoint_count` default **110**. Groups-only: `TF_VAR_endpoint_count=0`.
- Two Allowed Protocols (`ise_allowed_protocols` 0.3.4): 802.1X EAP and MAB PAP/ASCII.
- ACCESS_ACCEPT profiles: lab VLAN 10 data, 20 voice, 30 MAB. Authz: Phones → VLAN 20 (voice), Printers → VLAN 30 (MAB), all other groups → VLAN 10 (data). First-match.
- One Network Access policy set. Dot1X → Internal Users. MAB → Internal Endpoints continue-if-not-found.
- NAD `authentication_network_protocol` is `RADIUS`. Keep `tacacs_shared_secret`. Access stays `access-marketing`. No HQ/DC city tags. `nad_count` default stays 15000.

## Apply (after destroy)

Default `nad_count` is **15000**. Default `endpoint_count` is **110**. After destroy: `git pull`, `terraform init`, `load-env.ps1`, `terraform apply` creates the Location tree, every `devices.csv` switch, TACACS device-admin, wired 802.1X/MAB policy, **and** 110 lab MACs. After pull, `.env` needs both `NAD_TACACS_SECRET` and `NAD_RADIUS_SECRET` (env only; no secret in git). NAD protocol is `RADIUS` so 802.1X can use the NAD; `tacacs_shared_secret` stays. Empty TACACS or RADIUS secret with NADs to push fails. No switches: `TF_VAR_nad_count=0`. Groups-only (no MAC rows): `TF_VAR_endpoint_count=0`.

One PAN: Location NDGs were ~50 seconds each. Full apply (400 sites + 151 folders + 15,000 NADs) will take a long time. Do not apply from an agent.

## Next

1. Freeze this plan
2. `sites.yaml` + `access-groups.yaml` + command-set YAML
3. NAD generator (hostname + loopback + access group)
4. Terraform (or equivalent) to push ISE
5. Lab apply only after LAN is cleared
