output "what_apply_will_do" {
  description = "Counts for this apply. Default nads_to_push is 15000 (all of devices.csv). TF_VAR_nad_count=0 is policy-only."
  value = {
    access_ndgs                = length(local.ndgs)
    default_access_ndg         = local.default_access_ndg
    location_ndgs_type         = length(local.location_ndgs)
    location_ndgs_state        = length(local.state_location_ndgs)
    location_ndgs_site         = length(local.site_location_ndgs)
    tacacs_authc               = length(local.authc)
    tacacs_authz               = length(local.authz)
    endpoint_identity_groups   = length(local.endpoint_identity_groups)
    allowed_protocols          = length(local.allowed_protocols)
    authorization_profiles     = length(local.authorization_profiles)
    network_access_policy_sets = length(local.network_access_policy_sets)
    network_access_authc       = length(local.na_authc)
    network_access_authz       = length(local.na_authz)
    endpoints_to_push          = var.endpoint_count
    nads_in_csv                = length(local.devices)
    sample_nads_optional       = length(local.sample_nad_rows)
    nads_to_push               = var.nad_count
    pan                        = var.ise_host
  }
}
