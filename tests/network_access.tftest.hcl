# Wired 802.1X + MAB Network Access policy. mock_provider: no PAN.
# Policy checks cap endpoint_count=0 so this file does not plan 150k
# ise_endpoint rows (that default is tests/endpoints_enterprise.tftest.hcl).
# Lab endpoints.csv stays 110 inventory. Apply path is the enterprise CSV.
# Default nad_count stays 15000 — see nads_default.tftest.hcl.
mock_provider "ise" {}

run "wired_8021x_mab_policy" {
  command = plan

  variables {
    nad_count      = 0
    endpoint_count = 0
    user_password  = "mock-not-for-ise"
  }

  assert {
    condition     = length(csvdecode(trimprefix(file("${path.module}/endpoints.csv"), "\ufeff"))) == 110
    error_message = "Lab endpoints.csv stays 110 in Git (inventory only; not the apply path)."
  }

  assert {
    condition     = length(ise_endpoint_identity_group.this) == 11
    error_message = "Exactly eleven endpoint identity groups (CoS lock). Drop Workstation / IP-Phone / Printer."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Phones"].name == "Phones"
    error_message = "Phones endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["AP"].name == "AP"
    error_message = "AP endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Printers"].name == "Printers"
    error_message = "Printers endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["TVs"].name == "TVs"
    error_message = "TVs endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Badge_Readers"].name == "Badge_Readers"
    error_message = "Badge_Readers endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Cameras"].name == "Cameras"
    error_message = "Cameras endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["UPS"].name == "UPS"
    error_message = "UPS endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Powerstrips"].name == "Powerstrips"
    error_message = "Powerstrips endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Linux"].name == "Linux"
    error_message = "Linux endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["Windows"].name == "Windows"
    error_message = "Windows endpoint identity group must exist."
  }

  assert {
    condition     = ise_endpoint_identity_group.this["RFID_Readers"].name == "RFID_Readers"
    error_message = "RFID_Readers endpoint identity group must exist."
  }

  assert {
    condition     = !contains(keys(ise_endpoint_identity_group.this), "Workstation")
    error_message = "Workstation group is gone."
  }

  assert {
    condition     = !contains(keys(ise_endpoint_identity_group.this), "IP-Phone")
    error_message = "IP-Phone group is gone."
  }

  assert {
    condition     = !contains(keys(ise_endpoint_identity_group.this), "Printer")
    error_message = "Printer group is gone (replaced by Printers)."
  }

  assert {
    condition     = length(ise_endpoint.this) == 0
    error_message = "This policy run caps endpoint_count=0; default 150000 is tests/endpoints_enterprise.tftest.hcl."
  }

  assert {
    condition = alltrue([
      for e in csvdecode(trimprefix(file("${path.module}/endpoints.csv"), "\ufeff")) :
      startswith(e.mac, {
        Phones        = "00:04:f2:"
        AP            = "9c:e3:30:"
        Printers      = "9c:7b:ef:"
        TVs           = "64:1b:2f:"
        Badge_Readers = "00:30:8e:"
        Cameras       = "00:40:8c:"
        UPS           = "00:c0:b7:"
        Powerstrips   = "00:0d:5d:"
        Linux         = "00:c0:4f:"
        Windows       = "10:e7:c6:"
        RFID_Readers  = "00:16:25:"
      }[e.endpoint_identity_group])
    ])
    error_message = "Lab endpoints.csv must keep locked IEEE MA-L OUIs. Do not invent OUIs."
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
    condition     = length(ise_network_access_authorization_rule.authz) == 11
    error_message = "Eleven authz rules, one per endpoint identity group. First-match."
  }

  assert {
    condition     = ise_network_access_authorization_rule.authz["phones"].profiles == toset(["Wired_Voice"])
    error_message = "First-match authz phones must use Wired_Voice (VLAN 20)."
  }

  assert {
    condition     = ise_network_access_authorization_rule.authz["printers"].profiles == toset(["Wired_Printer"])
    error_message = "Authz printers must use Wired_Printer (VLAN 30 MAB)."
  }

  assert {
    condition     = ise_network_access_authorization_rule.authz["windows"].profiles == toset(["Wired_Data"])
    error_message = "Authz windows must use Wired_Data (VLAN 10)."
  }

  assert {
    condition     = ise_network_access_authorization_rule.authz["ap"].profiles == toset(["Wired_Data"])
    error_message = "Authz ap must use Wired_Data (VLAN 10)."
  }

  assert {
    condition     = !contains(keys(ise_network_access_authorization_rule.authz), "workstation")
    error_message = "Authz workstation rule is gone."
  }

  assert {
    condition     = !contains(keys(ise_network_access_authorization_rule.authz), "ip-phone")
    error_message = "Authz ip-phone rule is gone."
  }

  assert {
    condition     = !contains(keys(ise_network_access_authorization_rule.authz), "printer")
    error_message = "Authz printer rule is gone (replaced by printers)."
  }

  assert {
    condition     = local.default_access_ndg == "access-marketing"
    error_message = "Access stays access-marketing."
  }

  assert {
    condition     = output.what_apply_will_do.endpoints_to_push == 0
    error_message = "This policy run caps endpoints_to_push at 0."
  }

  assert {
    condition     = output.what_apply_will_do.endpoints_in_csv == 150000
    error_message = "endpoints_in_csv is endpoints_enterprise.csv (150000), not lab 110."
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

run "groups_only_zero_endpoints" {
  command = plan

  variables {
    nad_count      = 0
    endpoint_count = 0
    user_password  = "mock-not-for-ise"
  }

  assert {
    condition     = length(ise_endpoint.this) == 0
    error_message = "TF_VAR_endpoint_count=0 must skip MAC rows (groups still apply)."
  }

  assert {
    condition     = length(ise_endpoint_identity_group.this) == 11
    error_message = "Groups-only still creates the eleven identity groups."
  }

  assert {
    condition     = ise_network_access_policy_set.wired.name == "Wired 802.1X MAB"
    error_message = "Dot1X + MAB policy set stays when endpoint_count=0."
  }
}

run "endpoint_count_over_max_fails" {
  command = plan

  variables {
    nad_count      = 0
    endpoint_count = 150001
    user_password  = "mock-not-for-ise"
  }

  expect_failures = [
    var.endpoint_count,
  ]
}
