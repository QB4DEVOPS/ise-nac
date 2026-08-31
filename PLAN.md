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
| NDG tree | Country → Site → Type. Plus NAD groups: Marketing, HR, CEO, source-code |
| Command sets | T1–T4 ladder. Vendor (time-bound, NDG-scoped). Contractor. Auditor internal (all NADs, read-only). Auditor external (time-bound, read-only) |
| Generator | Stamps 15k NAD records off the tree (CSV) |
| ISE deploy | PAN / MnT / PSN split. Four regional PSNs in the story, two in the lab |
| Accounting | SOX = accounting + separation of duties (the T1–T4 ladder). PII lives in MnT and TACACS logs; in-region in the story |

Country stays **off** command sets and policy sets. It belongs on the NAD tree and on log residency, not on every rule.

## Out of v1

- Wired/wireless 802.1X, MAB, guest, unknown
- Dual PAN
- Per-nation ISE clusters / MnT split
- Standing up gear on the LAN until Robert clears it

## Next

1. Freeze this plan
2. YAML for NDG + command sets + identities
3. NAD generator
4. Terraform (or equivalent) to push ISE
5. Lab apply only after LAN is cleared
