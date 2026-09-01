# Expand Location for_each without talking to ISE.
# terraform validate does not evaluate each.value.ndg on grouped tuples;
# plan/apply does. This plan must see objects, not tuples.
mock_provider "ise" {}

run "state_and_site_location_are_objects" {
  command = plan

  # Policy-only so this run stays a Location for_each check (616 objects),
  # not 6,250 NAD creates. Default nad_count is 6250 — see nads_default.tftest.hcl.
  variables {
    nad_count = 0
  }

  assert {
    condition     = local.state_location_ndgs["California"].ndg == "California"
    error_message = "state_location_ndgs[California] must be an object with ndg, not a grouped tuple of site rows."
  }

  assert {
    condition     = local.state_location_ndgs["California"].description == "US state California"
    error_message = "state_location_ndgs[California] must carry a description on the object, not a tuple."
  }

  assert {
    condition     = !contains(keys(local.state_location_ndgs), "regional")
    error_message = "No state/country folder may be named regional (type-level only)."
  }

  assert {
    condition     = local.site_location_ndgs["us-los-angeles"].ise_name == "Location#All Locations#California#us-los-angeles"
    error_message = "site_location_ndgs[us-los-angeles] must be an object with the nested ISE path."
  }

  assert {
    condition     = ise_network_device_group.state_location["California"].name == "Location#All Locations#California"
    error_message = "state_location[California] planned name must interpolate each.value.ndg from an object."
  }

  assert {
    condition     = ise_network_device_group.site_location["us-los-angeles"].name == "Location#All Locations#California#us-los-angeles"
    error_message = "site_location[us-los-angeles] planned name must be the nested state/city path."
  }

  assert {
    condition     = local.default_access_ndg == "access-marketing"
    error_message = "Access stays access-marketing."
  }
}
