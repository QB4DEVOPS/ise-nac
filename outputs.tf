output "what_apply_will_do" {
  description = "Counts for this apply. NAD count must stay 0 unless TF_VAR_nad_count is set."
  value = {
    access_ndgs   = length(local.ndgs)
    location_ndgs = length(local.location_ndgs)
    tacacs_authc  = length(local.authc)
    tacacs_authz  = length(local.authz)
    nads_in_csv   = length(local.devices)
    sample_nads   = length(local.sample_nads)
    nads_to_push  = var.nad_count
    pan           = var.ise_host
  }
}
