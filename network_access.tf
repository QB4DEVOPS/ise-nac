# Wired 802.1X + MAB Network Access policy. Not Device Admin (that stays in main.tf).
# CiscoDevNet/ise 0.3.4 resources (verified, not invented):
#   ise_endpoint_identity_group
#   ise_endpoint                   (name, mac, group_id, static_group_assignment, static_profile_assignment)
#   ise_allowed_protocols          (Network Access; not ise_allowed_protocols_tacacs)
#   ise_authorization_profile      (access_type, vlan_name_id, vlan_tag_id, voice_domain_permission)
#   ise_network_access_policy_set
#   ise_network_access_authentication_rule
#   ise_network_access_authentication_rule_update_ranks
#   ise_network_access_authorization_rule  (profiles = set of names)
#   ise_network_access_authorization_rule_update_ranks
# 11 groups. 110 lab MACs (endpoints.csv, IEEE MA-L OUI + generated NIC suffix).
# Default endpoint_count=110. No guest.
# Schema cites:
#   https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/endpoint_identity_group
#   https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/endpoint
#   https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/allowed_protocols
#   https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/authorization_profile
#   https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/network_access_policy_set
#   https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/network_access_authentication_rule
#   https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/network_access_authorization_rule

resource "ise_endpoint_identity_group" "this" {
  for_each       = { for g in local.endpoint_identity_groups : g.name => g }
  name           = each.value.name
  description    = each.value.description
  system_defined = each.value.system_defined
}

# Lab MACs from endpoints.csv. Default endpoint_count=110 (all 11×10).
# Groups-only (no MAC rows): TF_VAR_endpoint_count=0. Do not dump 15k MACs.
# 0.3.4 required: name, mac, static_group_assignment, static_profile_assignment.
# group_id is the Identity Group ID (ise_endpoint_identity_group.id).
# MACs use locked IEEE MA-L OUIs; last 3 octets are generated. Not hardware.
resource "ise_endpoint" "this" {
  count = var.endpoint_count

  name                      = local.endpoints[count.index].mac
  mac                       = local.endpoints[count.index].mac
  description               = local.endpoints[count.index].description
  group_id                  = ise_endpoint_identity_group.this[local.endpoints[count.index].endpoint_identity_group].id
  static_group_assignment   = true
  static_profile_assignment = false

  lifecycle {
    precondition {
      condition     = var.endpoint_count <= length(local.endpoints)
      error_message = "endpoint_count cannot exceed endpoints.csv (${length(local.endpoints)}). Default is all ${length(local.endpoints)} lab MACs. Groups-only is TF_VAR_endpoint_count=0."
    }
  }
}

# Required 0.3.4 booleans come from allowed_protocols.yaml. Optional inner-method
# flags are null when the YAML row omits them (MAB has no EAP inner methods).
resource "ise_allowed_protocols" "this" {
  for_each = { for p in local.allowed_protocols : p.name => p }

  name                         = each.value.name
  description                  = try(each.value.description, "")
  process_host_lookup          = each.value.process_host_lookup
  allow_pap_ascii              = each.value.allow_pap_ascii
  allow_chap                   = each.value.allow_chap
  allow_ms_chap_v1             = each.value.allow_ms_chap_v1
  allow_ms_chap_v2             = each.value.allow_ms_chap_v2
  allow_eap_md5                = each.value.allow_eap_md5
  allow_leap                   = each.value.allow_leap
  allow_eap_tls                = each.value.allow_eap_tls
  allow_eap_ttls               = each.value.allow_eap_ttls
  allow_eap_fast               = each.value.allow_eap_fast
  allow_peap                   = each.value.allow_peap
  allow_teap                   = each.value.allow_teap
  allow_preferred_eap_protocol = each.value.allow_preferred_eap_protocol
  allow_weak_ciphers_for_eap   = each.value.allow_weak_ciphers_for_eap
  eap_tls_l_bit                = each.value.eap_tls_l_bit
  require_message_auth         = each.value.require_message_auth

  peap_allow_peap_eap_ms_chap_v2 = try(each.value.peap_allow_peap_eap_ms_chap_v2, null)
  peap_allow_peap_eap_tls        = try(each.value.peap_allow_peap_eap_tls, null)
  eap_ttls_pap_ascii             = try(each.value.eap_ttls_pap_ascii, null)
  eap_ttls_ms_chap_v2            = try(each.value.eap_ttls_ms_chap_v2, null)
  teap_eap_ms_chap_v2            = try(each.value.teap_eap_ms_chap_v2, null)
  teap_eap_tls                   = try(each.value.teap_eap_tls, null)
}

# access_type / vlan_name_id / vlan_tag_id / voice_domain_permission are 0.3.4 fields.
# dacl_name is a real 0.3.4 field; not set (no DACL objects in Git).
resource "ise_authorization_profile" "this" {
  for_each                = { for p in local.authorization_profiles : p.name => p }
  name                    = each.value.name
  description             = try(each.value.description, "")
  access_type             = each.value.access_type
  vlan_name_id            = tostring(each.value.vlan_name_id)
  vlan_tag_id             = tonumber(each.value.vlan_tag_id)
  voice_domain_permission = each.value.voice_domain_permission
}

resource "ise_network_access_policy_set" "wired" {
  name                      = local.wired_policy_set.name
  description               = local.wired_policy_set.description
  is_proxy                  = local.wired_policy_set.is_proxy
  rank                      = local.wired_policy_set.rank
  service_name              = ise_allowed_protocols.this[local.wired_policy_set.service_name].name
  state                     = local.wired_policy_set.state
  condition_type            = local.wired_policy_set.condition_type
  condition_is_negate       = local.wired_policy_set.condition_is_negate
  condition_attribute_name  = local.wired_policy_set.condition_attribute_name
  condition_attribute_value = local.wired_policy_set.condition_attribute_value
  condition_dictionary_name = local.wired_policy_set.condition_dictionary_name
  condition_operator        = local.wired_policy_set.condition_operator

  lifecycle {
    precondition {
      condition     = length(local.network_access_policy_sets) == 1
      error_message = "Exactly one Network Access policy set. Device Admin TACACS stays ise_device_admin_policy_set."
    }
  }
}

resource "ise_network_access_authentication_rule" "authc" {
  for_each                  = { for row in local.na_authc : row.name => row }
  policy_set_id             = ise_network_access_policy_set.wired.id
  name                      = each.value.name
  default                   = false
  state                     = "enabled"
  identity_source_name      = lookup(local.identity_source_name, each.value.identity_source, each.value.identity_source)
  if_auth_fail              = each.value.if_auth_fail
  if_user_not_found         = each.value.if_user_not_found
  if_process_fail           = each.value.if_process_fail
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_attribute_name  = each.value.condition_attribute_name
  condition_attribute_value = each.value.condition_attribute_value
  condition_dictionary_name = each.value.condition_dictionary_name
  condition_operator        = each.value.condition_operator
}

# ISE first-match order from network_access_authc.csv (order 1 → rank 0).
resource "ise_network_access_authentication_rule_update_ranks" "authc" {
  policy_set_id = ise_network_access_policy_set.wired.id
  rules = [
    for row in local.na_authc : {
      id   = ise_network_access_authentication_rule.authc[row.name].id
      rank = tonumber(row.order) - 1
    }
  ]
}

resource "ise_network_access_authorization_rule" "authz" {
  for_each                  = { for row in local.na_authz : row.name => row }
  policy_set_id             = ise_network_access_policy_set.wired.id
  name                      = each.value.name
  default                   = false
  state                     = "enabled"
  profiles                  = [ise_authorization_profile.this[each.value.profile].name]
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_dictionary_name = "IdentityGroup"
  condition_attribute_name  = "Name"
  condition_operator        = "equals"
  condition_attribute_value = "Endpoint Identity Groups:${each.value.endpoint_identity_group}"

  depends_on = [
    ise_endpoint_identity_group.this,
    ise_authorization_profile.this,
  ]
}

# ISE first-match order from network_access_authz.csv (order 1 → rank 0).
resource "ise_network_access_authorization_rule_update_ranks" "authz" {
  policy_set_id = ise_network_access_policy_set.wired.id
  rules = [
    for row in local.na_authz : {
      id   = ise_network_access_authorization_rule.authz[row.name].id
      rank = tonumber(row.order) - 1
    }
  ]
}
