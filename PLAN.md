# ISE NaC — Device Administration

Rebuild ISE from Git. Clone is the source of truth. If you have to click, we failed.

## Goal

Customer-ready **device administration** on Cisco ISE, expressed as Network as Code.

- Story scale: ~100k users, 400+ sites, 15k NADs, multinational
- Product: TACACS device admin
- RADIUS only for NADs that cannot speak TACACS
- 802.1X / MAB / guest are **out of v1**
- Ignore internode latency
- One Palo Alto as a choke. Dual-home is a later commit, after Git rebuild works
- CML is optional. Terraform is the truck. YAML is the policy

## v1 in Git

| Artifact | What it is |
| --- | --- |
| NDG tree | **Access groups only** (who can log into which NADs). Not a site tree |
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

400+ sites live in `sites.yaml`. Do not encode site in NDG. Excel copies: `sites.csv`, `ndgs.csv`, `tacacs_authc.csv`, `tacacs_authz.csv`.

## Management loopbacks

One loopback per NAD. Plan is 15k addresses, ~37 NADs per site at 400 sites. Give each site a `/24`.

- Block: `10.0.0.0/8`
- Per country: `10.{cc_id}.0.0/16` (`cc_id` from `sites.yaml`, 1–254)
- Per site: `10.{cc_id}.{site_id}.0/24` (`site_id` 1–254 per country)
- Device: `10.{cc_id}.{site_id}.{nn}/32` (`nn` 1–254)

Example: `usnyc-sw-01` → `10.1.1.1/32`

No overlap with underlay/P2P. Loopbacks are management only.

## NDG — access groups only

Four groups. That is the list.

| NDG | Who may administer those NADs |
| --- | --- |
| `access-marketing` | T1+ |
| `access-hr` | T2+ |
| `access-ceo` | T3+ |
| `access-sourcecode` | T4 |

Vendor is time-bound and scoped to one of these. Auditors are read-only across all four. Do not add Country or Site NDGs.

## Out of v1

- Wired/wireless 802.1X, MAB, guest, unknown
- Dual PAN
- Per-nation ISE clusters / MnT split
- Standing up gear on the LAN until Robert clears it

## Next

1. Freeze this plan
2. `sites.yaml` + `access-groups.yaml` + command-set YAML
3. NAD generator (hostname + loopback + access group)
4. Terraform (or equivalent) to push ISE
5. Lab apply only after LAN is cleared
