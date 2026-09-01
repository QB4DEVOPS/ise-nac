# Prove a normal apply (no TF_VAR_nad_count) pushes all of devices.csv.
# mock_provider: no PAN, no 192.168.1.90.
mock_provider "ise" {}

run "default_pushes_all_devices" {
  command = plan

  # Dummy for this mock plan only. Variable defaults in git stay empty.
  # Real secrets are NAD_TACACS_SECRET / NAD_RADIUS_SECRET (never in git).
  variables {
    nad_tacacs_secret = "mock-not-for-ise"
    nad_radius_secret = "mock-not-for-ise"
  }

  assert {
    condition     = var.nad_count == 6250
    error_message = "nad_count default must be 6250 so a normal apply pushes devices.csv."
  }

  assert {
    condition     = length(local.devices) == 6250
    error_message = "devices.csv must contain 6250 NAD rows."
  }

  assert {
    condition     = output.what_apply_will_do.nads_to_push == 6250
    error_message = "Default nads_to_push must be 6250 (all of devices.csv)."
  }

  assert {
    condition     = output.what_apply_will_do.nads_in_csv == 6250
    error_message = "Output nads_in_csv must match devices.csv (6250)."
  }

  assert {
    condition     = length(ise_network_device.nad) == 6250
    error_message = "Plan must create 6250 ise_network_device.nad instances at default."
  }

  assert {
    condition     = local.default_access_ndg == "access-marketing"
    error_message = "Access stays access-marketing. Do not round-robin."
  }

  # First NAD: Huntsville, Alabama. Access + nested site Location only.
  assert {
    condition = ise_network_device.nad[0].network_device_groups == tolist([
      "Access#All Access#access-marketing",
      "Location#All Locations#Alabama#us-huntsville",
    ])
    error_message = "NAD[0] must join access-marketing plus Location#All Locations#Alabama#us-huntsville."
  }

  # Next regional site (index 20): still access-marketing, not round-robin hr/ceo.
  assert {
    condition = ise_network_device.nad[20].network_device_groups == tolist([
      "Access#All Access#access-marketing",
      "Location#All Locations#Alaska#us-anchorage",
    ])
    error_message = "NAD[20] must join access-marketing plus Location#All Locations#Alaska#us-anchorage. Do not round-robin Access. Do not invent HQ/DC tags."
  }

  assert {
    condition     = ise_network_device.nad[0].authentication_network_protocol == "TACACS_PLUS"
    error_message = "NAD protocol stays TACACS_PLUS. Do not switch NADs to RADIUS."
  }

  assert {
    condition     = length(ise_network_device.nad[0].authentication_radius_shared_secret) > 0
    error_message = "NAD must set authentication_radius_shared_secret (ISE requires RADIUS secret even for TACACS_PLUS)."
  }

  assert {
    condition     = ise_tacacs_command_set.test.name == "test_cs"
    error_message = "TACACS command-set ISE names stay *_cs."
  }

  assert {
    condition     = ise_tacacs_profile.this["T1"].name == "T1_shell"
    error_message = "TACACS shell profile ISE names stay *_shell."
  }
}

run "policy_only_zero" {
  command = plan

  variables {
    nad_count = 0
  }

  assert {
    condition     = output.what_apply_will_do.nads_to_push == 0
    error_message = "TF_VAR_nad_count=0 must skip NADs (policy-only)."
  }

  assert {
    condition     = length(ise_network_device.nad) == 0
    error_message = "Policy-only plan must create zero NAD instances."
  }
}

run "empty_tacacs_secret_fails_when_pushing_nads" {
  command = plan

  variables {
    nad_count         = 1
    nad_tacacs_secret = ""
    nad_radius_secret = "mock-not-for-ise"
  }

  expect_failures = [
    ise_network_device.nad,
  ]
}

run "empty_radius_secret_fails_when_pushing_nads" {
  command = plan

  variables {
    nad_count         = 1
    nad_tacacs_secret = "mock-not-for-ise"
    nad_radius_secret = ""
  }

  expect_failures = [
    ise_network_device.nad,
  ]
}
