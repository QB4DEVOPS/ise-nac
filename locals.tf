locals {
  # Excel CSVs are UTF-8 with BOM. Terraform csvdecode needs the BOM stripped.
  ndgs    = csvdecode(trimprefix(file("${path.module}/ndgs.csv"), "\ufeff"))
  authc   = csvdecode(trimprefix(file("${path.module}/tacacs_authc.csv"), "\ufeff"))
  authz   = csvdecode(trimprefix(file("${path.module}/tacacs_authz.csv"), "\ufeff"))
  devices = csvdecode(trimprefix(file("${path.module}/devices.csv"), "\ufeff"))
  sites   = csvdecode(trimprefix(file("${path.module}/sites.csv"), "\ufeff"))

  # Type-level Location NDGs (siblings under All Locations).
  # ISE: Location#All Locations#{ndg}. NADs do not join these.
  location_ndg_rows = yamldecode(file("${path.module}/location_ndgs.yaml")).location_ndgs
  location_ndgs     = { for row in local.location_ndg_rows : row.ndg => row }

  # ISE NDG leaf: alphanumeric, underscore, minus, dot. '#' is the path
  # separator and must not appear in a leaf. Spaces/punctuation → '_'.
  # US region = slugged admin1 (state). Non-US region = cc (gb, de, …).
  # site_id is already legal ([a-z0-9-]+); no transform.
  # Current admin1 values only need space → underscore (New York → New_York).
  site_region = {
    for s in local.sites : s.id => (
      s.cc == "us" ? replace(s.admin1, " ", "_") : s.cc
    )
  }

  # Distinct regions: 51 US states (incl. District_of_Columbia) + 100 countries.
  region_ndgs = {
    for s in local.sites : local.site_region[s.id] => {
      ndg         = local.site_region[s.id]
      cc          = s.cc
      description = s.cc == "us" ? "US state ${s.admin1}" : "Country ${s.cc}"
    }...
  }

  # Nested site Location NDG. ISE:
  # Location#All Locations#{region}#{site_id}
  # Do not flatten under All Locations. Do not invent hq/dc city tags.
  site_location_ndgs = {
    for s in local.sites : s.id => {
      site_id     = s.id
      site_leaf   = s.id
      region      = local.site_region[s.id]
      ise_name    = "Location#All Locations#${local.site_region[s.id]}#${s.id}"
      description = s.admin1 != "" ? "${s.city}, ${s.admin1}" : s.city
    }
  }

  # Locked Access NDG until Robert tags devices. Not hr/ceo/sourcecode.
  # devices.csv has no Access column. Do not round-robin.
  default_access_ndg = "access-marketing"

  # Optional 8-row reference slice. Not the apply inventory.
  sample_nad_rows = csvdecode(trimprefix(file("${path.module}/sample_nads.csv"), "\ufeff"))

  # CSV says "ISE Internal Users". ISE's built-in store name is "Internal Users".
  identity_source_name = {
    "ISE Internal Users" = "Internal Users"
  }

  command_sets   = toset([for row in local.authz : row.command_set])
  shell_profiles = toset([for row in local.authz : row.shell_profile])
  # Live ISE names (T1, auditor-internal). Not the TACACS CS/profile bag.
  # T1 != T1_cs / T1_shell, so no suffix. Rename only if a name lands in that bag.
  identity_groups = toset([for row in local.authz : row.identity_group])

  # ISE TACACS names: alphanumeric, underscore, space. Hyphen is illegal
  # (auditor-external → auditor_external). Identity groups keep hyphens.
  # CSV keys stay T1.
  ise_tacacs_name = {
    for n in setunion(local.command_sets, local.shell_profiles) : n => replace(n, "-", "_")
  }

  # ISE ERS uses ONE shared name namespace. Every TACACS object gets a suffix
  # (underscore only). Locked ISE POST names; no two strings match:
  #   command sets: T1_cs T2_cs T3_cs T4_cs vendor_cs contractor_cs
  #                 auditor_internal_cs auditor_external_cs test_cs
  #   profiles:     T1_shell T2_shell T3_shell T4_shell vendor_shell
  #                 contractor_shell auditor_internal_shell auditor_external_shell
  # CSV keys stay T1. Identity groups / NDGs / authz rule names are not this map.
  ise_tacacs_command_set_name = {
    for n in local.command_sets : n => "${local.ise_tacacs_name[n]}_cs"
  }
  ise_tacacs_shell_profile_name = {
    for n in local.shell_profiles : n => "${local.ise_tacacs_name[n]}_shell"
  }

  # YAML objects keyed by CSV key (T1). .name is the ISE POST name (T1_cs / T1_shell).
  command_set_by_csv = {
    for cs in yamldecode(file("${path.module}/command_sets.yaml")).command_sets :
    trimsuffix(cs.name, "_cs") => cs
  }
  shell_profile_by_csv = {
    for sp in yamldecode(file("${path.module}/shell_profiles.yaml")).shell_profiles :
    trimsuffix(sp.name, "_shell") => sp
  }
}
