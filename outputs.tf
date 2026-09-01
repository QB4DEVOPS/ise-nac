output "what_apply_will_do" {
  description = "Counts for this apply. NAD count stays 0 unless TF_VAR_nad_count is set."
  value = {
    access_ndgs          = length(local.ndgs)
    default_access_ndg   = local.default_access_ndg
    location_ndgs_type   = length(local.location_ndgs)
    location_ndgs_region = length(local.region_ndgs)
    location_ndgs_site   = length(local.site_location_ndgs)
    tacacs_authc         = length(local.authc)
    tacacs_authz         = length(local.authz)
    nads_in_csv          = length(local.devices)
    sample_nads_optional = length(local.sample_nad_rows)
    nads_to_push         = var.nad_count
    pan                  = var.ise_host
  }
}
