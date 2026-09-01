output "what_apply_will_do" {
  description = "Counts for this apply. Default nads_to_push is 6250 (all of devices.csv). TF_VAR_nad_count=0 is policy-only."
  value = {
    access_ndgs          = length(local.ndgs)
    default_access_ndg   = local.default_access_ndg
    location_ndgs_type   = length(local.location_ndgs)
    location_ndgs_state  = length(local.state_location_ndgs)
    location_ndgs_site   = length(local.site_location_ndgs)
    tacacs_authc         = length(local.authc)
    tacacs_authz         = length(local.authz)
    nads_in_csv          = length(local.devices)
    sample_nads_optional = length(local.sample_nad_rows)
    nads_to_push         = var.nad_count
    pan                  = var.ise_host
  }
}
