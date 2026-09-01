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
    condition     = var.nad_count == 15000
    error_message = "nad_count default must be 15000 so a normal apply pushes devices.csv."
  }

  assert {
    condition     = length(local.devices) == 15000
    error_message = "devices.csv must contain 15000 NAD rows."
  }

  assert {
    condition     = output.what_apply_will_do.nads_to_push == 15000
    error_message = "Default nads_to_push must be 15000 (all of devices.csv)."
  }

  assert {
    condition     = output.what_apply_will_do.nads_in_csv == 15000
    error_message = "Output nads_in_csv must match devices.csv (15000)."
  }

  assert {
    condition     = length(ise_network_device.nad) == 15000
    error_message = "Plan must create 15000 ise_network_device.nad instances at default."
  }

  assert {
    condition     = local.default_access_ndg == "access-marketing"
    error_message = "Access stays access-marketing. Do not round-robin."
  }

  # First NAD: Huntsville, Alabama. Access + nested site Location only.
  # network_device_groups is a set (CiscoDevNet/ise 0.3.4); compare as toset, not list.
  assert {
    condition = ise_network_device.nad[0].network_device_groups == toset([
      "Access#All Access#access-marketing",
      "Location#All Locations#Alabama#us-huntsville",
    ])
    error_message = "NAD[0] must join access-marketing plus Location#All Locations#Alabama#us-huntsville."
  }

  # Next regional site (index 48): still access-marketing, not round-robin hr/ceo.
  # 50 regional × 48 switches; NAD[0..47] is Huntsville, NAD[48] is Anchorage.
  assert {
    condition = ise_network_device.nad[48].network_device_groups == toset([
      "Access#All Access#access-marketing",
      "Location#All Locations#Alaska#us-anchorage",
    ])
    error_message = "NAD[48] must join access-marketing plus Location#All Locations#Alaska#us-anchorage. Do not round-robin Access. Do not invent HQ/DC tags."
  }

  assert {
    condition     = ise_network_device.nad[0].authentication_network_protocol == "RADIUS"
    error_message = "NAD protocol is RADIUS so 802.1X/MAB can use the NAD. Keep tacacs_shared_secret."
  }

  assert {
    condition     = length(ise_network_device.nad[0].tacacs_shared_secret) > 0
    error_message = "Keep tacacs_shared_secret on NADs (both NAD secrets stay)."
  }

  assert {
    condition     = length(ise_network_device.nad[0].authentication_radius_shared_secret) > 0
    error_message = "NAD must set authentication_radius_shared_secret (NAD_RADIUS_SECRET). Protocol is RADIUS."
  }

  assert {
    condition     = ise_network_access_policy_set.wired.name == "Wired 802.1X MAB"
    error_message = "Wired Network Access policy set must exist alongside 15000 NADs."
  }

  assert {
    condition     = var.endpoint_count == 0
    error_message = "endpoint_count default stays 0 at full NAD inventory."
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
