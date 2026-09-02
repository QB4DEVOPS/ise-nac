# Lab Internal Users from users.csv. mock_provider: no PAN.
# Default user_count is 8 (one per TACACS identity group).
# House style matches nad_count / endpoint_count: lab inventory by default, 0 skips.
# Dummy user_password is for this mock plan only. Real secret stays in .env.
mock_provider "ise" {}

run "lab_internal_users" {
  command = plan

  variables {
    nad_count      = 0
    endpoint_count = 0
    user_password  = "mock-not-for-ise"
  }

  assert {
    condition     = var.user_count == 8
    error_message = "user_count default must be 8 (one lab Internal User per TACACS identity group)."
  }

  assert {
    condition     = length(local.users) == 8
    error_message = "users.csv must contain 8 lab Internal Users."
  }

  assert {
    condition     = length(ise_internal_user.this) == 8
    error_message = "Default apply must plan 8 ise_internal_user lab accounts."
  }

  assert {
    condition     = length(distinct([for u in ise_internal_user.this : u.name])) == 8
    error_message = "All 8 lab usernames must be unique."
  }

  assert {
    condition     = ise_internal_user.this[0].name == "lab-t1"
    error_message = "First lab Internal User must be lab-t1 (T1)."
  }

  assert {
    condition     = local.users[0].identity_group == "T1"
    error_message = "lab-t1 must join TACACS identity group T1."
  }

  assert {
    condition     = ise_internal_user.this[1].name == "lab-t2"
    error_message = "Second lab Internal User must be lab-t2 (T2)."
  }

  assert {
    condition     = local.users[3].identity_group == "T4"
    error_message = "lab-t4 must join TACACS identity group T4."
  }

  assert {
    condition     = local.users[4].identity_group == "vendor"
    error_message = "lab-vendor must join TACACS identity group vendor."
  }

  assert {
    condition     = local.users[5].identity_group == "contractor"
    error_message = "lab-contractor must join TACACS identity group contractor."
  }

  assert {
    condition     = local.users[6].identity_group == "auditor-internal"
    error_message = "auditor-internal keeps the hyphen from tacacs_authz.csv."
  }

  assert {
    condition     = ise_internal_user.this[7].name == "lab-auditor-external"
    error_message = "Last lab Internal User must be lab-auditor-external."
  }

  assert {
    condition     = local.users[7].username == "lab-auditor-external"
    error_message = "users.csv last username must be lab-auditor-external."
  }

  assert {
    condition     = local.users[7].identity_group == "auditor-external"
    error_message = "auditor-external keeps the hyphen from tacacs_authz.csv."
  }

  assert {
    condition     = !contains(keys(local.users[0]), "password")
    error_message = "users.csv must not contain a password column."
  }

  assert {
    condition     = ise_internal_user.this[0].change_password == false
    error_message = "Lab Internal Users must set change_password=false so first login works."
  }

  assert {
    condition     = ise_internal_user.this[0].enabled == true
    error_message = "Lab Internal Users must be enabled (0.3.4 enabled)."
  }

  assert {
    condition     = ise_internal_user.this[0].password_id_store == "Internal Users"
    error_message = "password_id_store must be Internal Users (0.3.4)."
  }

  assert {
    condition     = ise_internal_user.this[0].password_never_expires == true
    error_message = "Lab Internal Users set password_never_expires (0.3.4, ISE 3.2+)."
  }

  assert {
    condition     = contains(keys(ise_user_identity_group.this), "T1")
    error_message = "T1 user identity group must still exist."
  }

  assert {
    condition     = contains(keys(ise_user_identity_group.this), "auditor-internal")
    error_message = "auditor-internal user identity group must still exist."
  }

  assert {
    condition     = length(ise_user_identity_group.this) == 8
    error_message = "Eight TACACS user identity groups stay (T1–T4, vendor, contractor, auditor-*)."
  }

  assert {
    condition     = ise_device_admin_policy_set.tacacs.name == "Device Admin TACACS"
    error_message = "TACACS Device Admin policy set stays as-is."
  }

  assert {
    condition     = ise_tacacs_command_set.test.name == "test_cs"
    error_message = "TACACS GUI canary test_cs stays."
  }

  assert {
    condition     = ise_network_access_policy_set.wired.name == "Wired 802.1X MAB"
    error_message = "Wired 802.1X + MAB policy set stays."
  }

  assert {
    condition     = local.default_access_ndg == "access-marketing"
    error_message = "Access stays access-marketing."
  }

  assert {
    condition     = output.what_apply_will_do.users_to_push == 8
    error_message = "users_to_push must be 8 at default."
  }

  assert {
    condition     = output.what_apply_will_do.users_in_csv == 8
    error_message = "users_in_csv must be 8."
  }
}

run "users_only_zero" {
  command = plan

  variables {
    nad_count      = 0
    user_count     = 0
    endpoint_count = 0
  }

  assert {
    condition     = length(ise_internal_user.this) == 0
    error_message = "TF_VAR_user_count=0 must skip Internal User rows (groups still apply)."
  }

  assert {
    condition     = length(ise_user_identity_group.this) == 8
    error_message = "Skipping users still creates the eight TACACS identity groups."
  }

  assert {
    condition     = ise_device_admin_policy_set.tacacs.name == "Device Admin TACACS"
    error_message = "TACACS stays when user_count=0."
  }
}

run "empty_password_fails_when_pushing_users" {
  command = plan

  variables {
    nad_count      = 0
    user_count     = 1
    user_password  = ""
    endpoint_count = 0
  }

  expect_failures = [
    ise_internal_user.this,
  ]
}

run "user_count_over_max_fails" {
  command = plan

  variables {
    nad_count      = 0
    user_count     = 9
    user_password  = "mock-not-for-ise"
    endpoint_count = 0
  }

  expect_failures = [
    var.user_count,
  ]
}
