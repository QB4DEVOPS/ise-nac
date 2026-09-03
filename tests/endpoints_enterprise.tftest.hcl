# Apply path: endpoints_enterprise.csv. Default endpoint_count=150000.
# Lab endpoints.csv stays 110 in Git and is not csvdecode'd by locals.tf.
# mock_provider: no PAN. nad_count=0 and user_count=0 so this run plans
# 150k ise_endpoint only (not 15k NADs + 8 users on top).
# Per-group counts: O(1) index boundaries here. Full 150k scans belong in
# python3 scripts/generate_enterprise_endpoints.py --verify and nac-validate.
mock_provider "ise" {}

run "enterprise_default_150000" {
  command = plan

  variables {
    nad_count  = 0
    user_count = 0
  }

  assert {
    condition     = var.endpoint_count == 150000
    error_message = "endpoint_count default must be 150000 (endpoints_enterprise.csv)."
  }

  assert {
    condition     = length(local.endpoints) == 150000
    error_message = "Apply path must csvdecode endpoints_enterprise.csv (150000 rows)."
  }

  assert {
    condition     = length(ise_endpoint.this) == 150000
    error_message = "Default apply must plan 150000 ise_endpoint rows from the enterprise CSV."
  }

  assert {
    condition     = !strcontains(file("${path.module}/locals.tf"), "file(\"$${path.module}/endpoints.csv\")")
    error_message = "locals.tf must not file() endpoints.csv (lab 110 is not the apply path)."
  }

  assert {
    condition     = strcontains(file("${path.module}/locals.tf"), "file(\"$${path.module}/endpoints_enterprise.csv\")")
    error_message = "locals.tf must file() endpoints_enterprise.csv for ise_endpoint."
  }

  assert {
    condition     = length(csvdecode(trimprefix(file("${path.module}/endpoints.csv"), "\ufeff"))) == 110
    error_message = "Lab endpoints.csv stays 110 in Git (inventory only; do not apply both)."
  }

  assert {
    condition     = local.endpoints[0].endpoint_identity_group == "Phones"
    error_message = "First enterprise row is Phones."
  }

  assert {
    condition     = local.endpoints[1].endpoint_identity_group == "Windows"
    error_message = "Second enterprise row is Windows (same desk)."
  }

  assert {
    condition     = local.endpoints[0].desk == local.endpoints[1].desk
    error_message = "Phone and PC share the same desk."
  }

  assert {
    condition = (
      local.endpoints[0].switch == local.endpoints[1].switch &&
      local.endpoints[0].port == local.endpoints[1].port &&
      local.endpoints[0].site == local.endpoints[1].site
    )
    error_message = "Phone and PC share switch, port, and site."
  }

  assert {
    condition     = startswith(ise_endpoint.this[0].mac, "00:04:f2:")
    error_message = "First apply MAC is Phones IEEE MA-L 00:04:F2 (Polycom)."
  }

  assert {
    condition     = startswith(ise_endpoint.this[1].mac, "10:e7:c6:")
    error_message = "Second apply MAC is Windows IEEE MA-L 10:E7:C6 (Hewlett Packard)."
  }

  assert {
    condition     = ise_endpoint.this[0].name == ise_endpoint.this[0].mac
    error_message = "ise_endpoint.name must be the MAC (0.3.4)."
  }

  assert {
    condition     = ise_endpoint.this[0].static_group_assignment == true
    error_message = "ise_endpoint.static_group_assignment must be true (0.3.4 required)."
  }

  assert {
    condition     = ise_endpoint.this[0].static_profile_assignment == false
    error_message = "ise_endpoint.static_profile_assignment must be false."
  }

  assert {
    condition     = strcontains(lower(ise_endpoint.this[0].description), "not hardware")
    error_message = "ise_endpoint description must say the MAC is not hardware."
  }

  assert {
    condition = (
      local.endpoints[141998].endpoint_identity_group == "Phones" &&
      local.endpoints[141999].endpoint_identity_group == "Windows" &&
      local.endpoints[141998].desk == "desk-071000" &&
      local.endpoints[141999].desk == "desk-071000"
    )
    error_message = "Last desk is desk-071000 (71000 desks); phone+PC still paired."
  }

  assert {
    condition     = local.endpoints[142000].endpoint_identity_group == "AP"
    error_message = "First non-desk row (after 71000 desks) is AP."
  }

  assert {
    condition     = local.endpoints[142000].desk == ""
    error_message = "Non-desk rows use an empty desk column."
  }

  assert {
    condition     = local.endpoints[142000].port == "Gi1/0/6"
    error_message = "Non-desk port is Gi1/0/6 (above desk range Gi1/0/1-5)."
  }

  assert {
    condition     = startswith(ise_endpoint.this[142000].mac, "9c:e3:30:")
    error_message = "AP MAC is IEEE MA-L 9C:E3:30 (Cisco Meraki)."
  }

  assert {
    condition     = local.endpoints[144249].endpoint_identity_group == "AP" && local.endpoints[144250].endpoint_identity_group == "Printers"
    error_message = "AP is 2250 rows (142000-144249); Printers start at 144250."
  }

  assert {
    condition     = local.endpoints[149849].endpoint_identity_group == "Powerstrips" && local.endpoints[149850].endpoint_identity_group == "RFID_Readers"
    error_message = "Powerstrips end at 149849; RFID_Readers are the last 150 rows."
  }

  assert {
    condition     = local.endpoints[149999].endpoint_identity_group == "RFID_Readers"
    error_message = "Last enterprise row is RFID_Readers."
  }

  assert {
    condition     = output.what_apply_will_do.endpoints_to_push == 150000
    error_message = "endpoints_to_push default is 150000."
  }

  assert {
    condition     = output.what_apply_will_do.endpoints_in_csv == 150000
    error_message = "endpoints_in_csv is the enterprise file (150000), not lab 110."
  }
}
