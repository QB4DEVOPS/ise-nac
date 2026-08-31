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

  # ISE TACACS command-set / shell-profile names: alphanumeric, underscore, space.
  # Hyphen is illegal (auditor-external → auditor_external). CSV stays the Excel original.
  ise_tacacs_name = {
    for n in setunion(local.command_sets, local.shell_profiles) : n => replace(n, "-", "_")
  }
}
