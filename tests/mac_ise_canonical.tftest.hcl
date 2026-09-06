# ISE ERS stores MAC as uppercase colon-hex. Apply path must upper() the
# lowercase enterprise CSV so refresh does not churn on case alone.
# Two rows only — the 150k default plan lives in endpoints_enterprise.tftest.hcl.
mock_provider "ise" {}

run "ise_canonical_uppercase_mac" {
  command = plan

  variables {
    nad_count       = 0
    user_count      = 0
    endpoint_count  = 2
  }

  assert {
    condition     = ise_endpoint.this[0].mac == "00:04:F2:67:5C:B9"
    error_message = "Apply-path MAC must be ISE uppercase (00:04:F2:67:5C:B9), not CSV lowercase."
  }

  assert {
    condition     = ise_endpoint.this[1].mac == "10:E7:C6:0C:3A:0A"
    error_message = "Second apply-path MAC must be ISE uppercase (10:E7:C6:0C:3A:0A)."
  }

  assert {
    condition     = ise_endpoint.this[0].name == ise_endpoint.this[0].mac
    error_message = "ise_endpoint.name must match the ISE-canonical MAC."
  }

  assert {
    condition     = ise_endpoint.this[0].mac == upper(local.endpoints[0].mac)
    error_message = "ise_endpoint.mac must be upper() of the enterprise CSV MAC."
  }

  assert {
    condition     = local.endpoints[0].mac == "00:04:f2:67:5c:b9"
    error_message = "endpoints_enterprise.csv stays lowercase (generator house rule)."
  }

  assert {
    condition     = length(csvdecode(trimprefix(file("${path.module}/endpoints.csv"), "\ufeff"))) == 110
    error_message = "Lab endpoints.csv stays 110 in Git."
  }
}
