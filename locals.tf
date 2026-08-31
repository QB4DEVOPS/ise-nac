locals {
  # Excel CSVs are UTF-8 with BOM. Terraform csvdecode needs the BOM stripped.
  ndgs    = csvdecode(trimprefix(file("${path.module}/ndgs.csv"), "\ufeff"))
  authc   = csvdecode(trimprefix(file("${path.module}/tacacs_authc.csv"), "\ufeff"))
  authz   = csvdecode(trimprefix(file("${path.module}/tacacs_authz.csv"), "\ufeff"))
  devices = csvdecode(trimprefix(file("${path.module}/devices.csv"), "\ufeff"))

  # CSV says "ISE Internal Users". ISE's built-in store name is "Internal Users".
  identity_source_name = {
    "ISE Internal Users" = "Internal Users"
  }

  command_sets    = toset([for row in local.authz : row.command_set])
  shell_profiles  = toset([for row in local.authz : row.shell_profile])
  identity_groups = toset([for row in local.authz : row.identity_group])

  # ISE TACACS command-set names: alphanumeric, underscore, space.
  # Hyphen is illegal (auditor-external → auditor_external). Identity groups keep hyphens.
  # CSV/YAML tier keys stay T1, vendor, contractor, auditor_internal, …
  ise_tacacs_name = {
    for n in setunion(local.command_sets, local.shell_profiles) : n => replace(n, "-", "_")
  }

  # ISE ERS uses ONE shared name namespace for TACACS command sets AND shell
  # profiles. A profile named T1 400s when command set T1 exists (contractor
  # failed the same way). Profile ISE names get a _shell suffix. No hyphens.
  ise_tacacs_shell_profile_name = {
    for n in local.shell_profiles : n => "${local.ise_tacacs_name[n]}_shell"
  }

  # IOS commands and session_attributes live in YAML (NaC). Terraform POSTs these to ISE.
  command_set_by_name = {
    for cs in yamldecode(file("${path.module}/command_sets.yaml")).command_sets :
    cs.name => cs
  }
  shell_profile_by_name = {
    for sp in yamldecode(file("${path.module}/shell_profiles.yaml")).shell_profiles :
    sp.name => sp
  }
}
