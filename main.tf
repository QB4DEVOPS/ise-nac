provider "ise" {
  url      = "https://${var.ise_host}"
  username = var.ise_username
  insecure = true
  # Password: ISE_PASSWORD from the environment / .env (never from git).
}

# GUI canary. TARS owns the NAC; Terraform creates this. Do not click ISE to make it.
# Apply only this object: terraform apply -target=ise_tacacs_command_set.test
# Resource address stays .test. ISE name is test_cs (every TACACS object is suffixed).
# ISE-legal: show / version / PERMIT. No regex. No profile named test_cs.
# May 400 until Device Admin / TACACS is licensed; still ship the resource.
resource "ise_tacacs_command_set" "test" {
  name             = "test_cs"
  description      = "TARS GUI canary. show version only."
  permit_unmatched = false
  commands = [
    {
      grant     = "PERMIT"
      command   = "show"
      arguments = "version"
    }
  ]
}

# New NDG type "Access" — who may administer which NADs.
resource "ise_network_device_group" "access_root" {
  name        = "Access#All Access"
  description = "Device-admin access groups. Who may log into which NADs."
  root_group  = "Access"
}

resource "ise_network_device_group" "ndg" {
  for_each    = { for row in local.ndgs : row.ndg => row }
  name        = "Access#All Access#${each.value.ndg}"
  description = each.value.description
  root_group  = "Access"
  depends_on  = [ise_network_device_group.access_root]
}

# ISE already has Location / All Locations. Do not recreate that root.
# Type-level children only (regional, branch, hq, dc). No per-city NDGs.
resource "ise_network_device_group" "location" {
  for_each    = local.location_ndgs
  name        = "Location#All Locations#${each.value.ndg}"
  description = each.value.description
  root_group  = "Location"
}

# Empty identity groups. No users and no passwords.
# Names stay as applied (T1, auditor-internal). They are not in the TACACS
# command-set + profile ISE name bag (T1_cs, T1_shell, …). Suffix only if
# an identity group string later equals a command-set or profile ISE name.
resource "ise_user_identity_group" "this" {
  for_each    = local.identity_groups
  name        = each.value
  description = "Device-admin identity group from tacacs_authz.csv"
}

# IOS-XE command sets from command_sets.yaml. T4 may permit unmatched; others do not.
# Look up by CSV key (T1). POST the YAML name: (T1_cs).
resource "ise_tacacs_command_set" "this" {
  for_each         = local.command_sets
  name             = local.command_set_by_csv[local.ise_tacacs_name[each.value]].name
  description      = try(local.command_set_by_csv[local.ise_tacacs_name[each.value]].description, "TACACS command set ${local.command_set_by_csv[local.ise_tacacs_name[each.value]].name}")
  permit_unmatched = try(local.command_set_by_csv[local.ise_tacacs_name[each.value]].permit_unmatched, false)
  commands = [
    for c in try(local.command_set_by_csv[local.ise_tacacs_name[each.value]].commands, []) : {
      grant     = c.grant
      command   = c.command
      arguments = c.arguments
    }
  ]
}

# Shell profiles from shell_profiles.yaml. CiscoDevNet/ise 0.3.4:
# session_attributes = [{ type = "MANDATORY"|"OPTIONAL", name, value }].
# T1/auditor_* priv-lvl 1; everyone else 15. Empty profiles 400 on ISE 3.5.
# Look up by CSV key (T1). POST the YAML name: (T1_shell).
resource "ise_tacacs_profile" "this" {
  for_each    = local.shell_profiles
  name        = local.shell_profile_by_csv[local.ise_tacacs_name[each.value]].name
  description = try(local.shell_profile_by_csv[local.ise_tacacs_name[each.value]].description, "TACACS shell profile ${local.shell_profile_by_csv[local.ise_tacacs_name[each.value]].name}")
  session_attributes = [
    for a in local.shell_profile_by_csv[local.ise_tacacs_name[each.value]].session_attributes : {
      type  = a.type
      name  = a.name
      value = tostring(a.value)
    }
  ]

  # Command sets first so a shared-namespace create cannot race.
  depends_on = [
    ise_tacacs_command_set.this,
    ise_tacacs_command_set.test,
  ]
}

resource "ise_allowed_protocols_tacacs" "tacacs" {
  name             = "TACACS"
  description      = "TACACS device admin from tacacs_authc.csv"
  allow_pap_ascii  = true
  allow_chap       = true
  allow_ms_chap_v1 = true
}

resource "ise_device_admin_policy_set" "tacacs" {
  name                      = "Device Admin TACACS"
  description               = "TACACS device administration from Git"
  is_proxy                  = false
  rank                      = 0
  service_name              = ise_allowed_protocols_tacacs.tacacs.name
  state                     = "enabled"
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
}

resource "ise_device_admin_authentication_rule" "authc" {
  for_each                  = { for row in local.authc : row.name => row }
  policy_set_id             = ise_device_admin_policy_set.tacacs.id
  name                      = each.value.name
  default                   = false
  state                     = "enabled"
  identity_source_name      = lookup(local.identity_source_name, each.value.identity_source, each.value.identity_source)
  if_auth_fail              = each.value.if_auth_fail
  if_user_not_found         = each.value.if_user_not_found
  if_process_fail           = each.value.if_process_fail
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
}

# ISE first-match order from tacacs_authc.csv (order 1 → rank 0).
resource "ise_device_admin_authentication_rule_update_ranks" "authc" {
  policy_set_id = ise_device_admin_policy_set.tacacs.id
  rules = [
    for row in local.authc : {
      id   = ise_device_admin_authentication_rule.authc[row.name].id
      rank = tonumber(row.order) - 1
    }
  ]
}

resource "ise_device_admin_authorization_rule" "authz" {
  for_each      = { for row in local.authz : row.name => row }
  policy_set_id = ise_device_admin_policy_set.tacacs.id
  name          = each.value.name
  default       = false
  state         = "enabled"
  # .name is the ISE POST name (T1_cs / T1_shell), not a hardcoded CSV string.
  command_sets   = [ise_tacacs_command_set.this[each.value.command_set].name]
  profile        = ise_tacacs_profile.this[each.value.shell_profile].name
  condition_type = "ConditionAndBlock"
  children = [
    {
      condition_type  = "ConditionAttributes"
      is_negate       = false
      dictionary_name = "IdentityGroup"
      attribute_name  = "Name"
      operator        = "equals"
      attribute_value = "User Identity Groups:${each.value.identity_group}"
    },
    {
      condition_type  = "ConditionAttributes"
      is_negate       = false
      dictionary_name = "DEVICE"
      attribute_name  = "Access"
      operator        = "equals"
      attribute_value = "All Access#${each.value.ndg}"
    },
  ]

  depends_on = [
    ise_network_device_group.ndg,
    ise_user_identity_group.this,
  ]
}

# ISE first-match order from tacacs_authz.csv (order 1 → rank 0).
resource "ise_device_admin_authorization_rule_update_ranks" "authz" {
  policy_set_id = ise_device_admin_policy_set.tacacs.id
  rules = [
    for row in local.authz : {
      id   = ise_device_admin_authorization_rule.authz[row.name].id
      rank = tonumber(row.order) - 1
    }
  ]
}
