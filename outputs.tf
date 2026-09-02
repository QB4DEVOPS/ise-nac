output "what_apply_will_do" {
  description = "Counts for this apply. Default nads_to_push is 15000 (all of devices.csv). Default endpoints_to_push is 110 (all of endpoints.csv). Default users_to_push is 8 (all of users.csv). TF_VAR_nad_count=0 is no switches. TF_VAR_endpoint_count=0 is groups-only (no MAC rows). TF_VAR_user_count=0 skips Internal User rows."
  value = {
    access_ndgs                = length(local.ndgs)
    default_access_ndg         = local.default_access_ndg
    location_ndgs_type         = length(local.location_ndgs)
    location_ndgs_state        = length(local.state_location_ndgs)
    location_ndgs_site         = length(local.site_location_ndgs)
    tacacs_authc               = length(local.authc)
    tacacs_authz               = length(local.authz)
    identity_groups            = length(local.identity_groups)
    endpoint_identity_groups   = length(local.endpoint_identity_groups)
    allowed_protocols          = length(local.allowed_protocols)
    authorization_profiles     = length(local.authorization_profiles)
    network_access_policy_sets = length(local.network_access_policy_sets)
    network_access_authc       = length(local.na_authc)
    network_access_authz       = length(local.na_authz)
    endpoints_in_csv           = length(local.endpoints)
    endpoints_to_push          = var.endpoint_count
    users_in_csv               = length(local.users)
    users_to_push              = var.user_count
    nads_in_csv                = length(local.devices)
    sample_nads_optional       = length(local.sample_nad_rows)
    nads_to_push               = var.nad_count
    pan                        = var.ise_host
  }
}
