output "what_apply_will_do" {
  description = "Counts for this apply. NAD count must stay 0 on first apply."
  value = {
    ndgs         = length(local.ndgs)
    tacacs_authc = length(local.authc)
    tacacs_authz = length(local.authz)
    nads_in_csv  = length(local.devices)
    nads_to_push = var.nad_count
    pan          = var.ise_host
  }
}
