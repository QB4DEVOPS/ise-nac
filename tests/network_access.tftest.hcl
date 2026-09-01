# Wired 802.1X + MAB Network Access policy. mock_provider: no PAN.
# Policy-only (nad_count=0): groups, protocols, profiles, one policy set.
# Default nad_count stays 15000 — see nads_default.tftest.hcl.
mock_provider "ise" {}

run "wired_8021x_mab_policy" {
  command = plan

  variables {
    nad_count = 0
  }

  assert {
    condition     = var.endpoint_count == 0
    error_message = "endpoint_count default must stay 0. Groups only. No MAC list."
  }

  assert {
    condition     = length(ise_endpoint_identity_group.this) == 3
    error_message = "Exactly three endpoint identity groups: Workstation, IP-Phone, Printer."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Workstation"].name == "Workstation"
    error_message = "Workstation endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["IP-Phone"].name == "IP-Phone"
    error_message = "IP-Phone endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Printer"].name == "Printer"
    error_message = "Printer endpoint identity group must exist."
  }

  assert {
    condition     = length(ise_allowed_protocols.this) == 2
    error_message = "Exactly two ise_allowed_protocols (0.3.4 Network Access). Not TACACS."
  }

  assert {
    condition     = ise_allowed_protocols.this["Wired_8021X"].allow_eap_tls == true
    error_message = "Wired_8021X must allow EAP-TLS."
  }

  assert {
    condition     = ise_allowed_protocols.this["Wired_8021X"].allow_peap == true
    error_message = "Wired_8021X must allow PEAP."
  }

  assert {
    condition     = ise_allowed_protocols.this["Wired_8021X"].allow_pap_ascii == false
    error_message = "Wired_8021X is EAP, not PAP/ASCII."
  }

  assert {
    condition     = ise_allowed_protocols.this["Wired_MAB"].process_host_lookup == true
    error_message = "Wired_MAB must process host lookup."
  }

  assert {
    condition     = ise_allowed_protocols.this["Wired_MAB"].allow_pap_ascii == true
    error_message = "Wired_MAB must allow PAP/ASCII."
  }

  assert {
    condition     = ise_allowed_protocols.this["Wired_MAB"].allow_eap_tls == false
    error_message = "Wired_MAB is PAP/ASCII, not EAP."
  }

  assert {
    condition     = length(ise_authorization_profile.this) == 3
    error_message = "Exactly three ACCESS_ACCEPT authorization profiles."
  }

  assert {
    condition     = ise_authorization_profile.this["Wired_Data"].access_type == "ACCESS_ACCEPT"
    error_message = "Wired_Data access_type must be ACCESS_ACCEPT (0.3.4)."
  }

  assert {
    condition     = ise_authorization_profile.this["Wired_Data"].vlan_name_id == "10"
    error_message = "Wired_Data vlan_name_id must be 10 (0.3.4 vlan_name_id)."
  }

  assert {
    condition     = ise_authorization_profile.this["Wired_Voice"].vlan_name_id == "20"
    error_message = "Wired_Voice vlan_name_id must be 20."
  }

  assert {
    condition     = ise_authorization_profile.this["Wired_Voice"].voice_domain_permission == true
    error_message = "Wired_Voice must set voice_domain_permission (0.3.4)."
  }

  assert {
    condition     = ise_authorization_profile.this["Wired_Printer"].vlan_name_id == "30"
    error_message = "Wired_Printer vlan_name_id must be 30 (MAB)."
  }

  assert {
    condition     = ise_authorization_profile.this["Wired_Printer"].access_type == "ACCESS_ACCEPT"
    error_message = "Wired_Printer access_type must be ACCESS_ACCEPT."
  }

  assert {
    condition     = ise_network_access_policy_set.wired.name == "Wired 802.1X MAB"
    error_message = "Exactly one Network Access policy set named Wired 802.1X MAB."
  }

  assert {
    condition     = ise_network_access_policy_set.wired.service_name == "Wired_8021X"
    error_message = "Policy set service_name must be Wired_8021X (0.3.4 binds one Allowed Protocols name)."
  }

  assert {
    condition     = ise_device_admin_policy_set.tacacs.name == "Device Admin TACACS"
    error_message = "TACACS Device Admin policy set stays as-is."
  }

  assert {
    condition     = ise_network_access_authentication_rule.authc["Dot1X"].identity_source_name == "Internal Users"
    error_message = "Dot1X must use Internal Users."
  }

  assert {
    condition     = ise_network_access_authentication_rule.authc["MAB"].identity_source_name == "Internal Endpoints"
    error_message = "MAB must use Internal Endpoints."
  }

  assert {
    condition     = ise_network_access_authentication_rule.authc["MAB"].if_user_not_found == "CONTINUE"
    error_message = "MAB if_user_not_found must be CONTINUE."
  }

  assert {
    condition     = ise_network_access_authorization_rule.authz["ip-phone"].profiles == toset(["Wired_Voice"])
    error_message = "First-match authz ip-phone must use Wired_Voice."
  }

  assert {
    condition     = ise_network_access_authorization_rule.authz["workstation"].profiles == toset(["Wired_Data"])
    error_message = "Authz workstation must use Wired_Data."
  }

  assert {
    condition     = ise_network_access_authorization_rule.authz["printer"].profiles == toset(["Wired_Printer"])
    error_message = "Authz printer must use Wired_Printer."
  }

  assert {
    condition     = local.default_access_ndg == "access-marketing"
    error_message = "Access stays access-marketing."
  }

  assert {
    condition     = output.what_apply_will_do.endpoints_to_push == 0
    error_message = "endpoints_to_push must be 0."
  }

  assert {
    condition     = length(ise_tacacs_command_set.this) > 0
    error_message = "TACACS command sets stay (*_cs)."
  }

  assert {
    condition     = ise_tacacs_profile.this["T1"].name == "T1_shell"
    error_message = "TACACS shell profiles stay (*_shell)."
  }
}

run "endpoint_count_nonzero_fails" {
  command = plan

  variables {
    nad_count      = 0
    endpoint_count = 1
  }

  expect_failures = [
    var.endpoint_count,
  ]
}
