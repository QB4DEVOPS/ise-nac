# Optional sample NADs. Default count is 0 so a normal apply does not push 6250.
# Curated sample (sample_nads.csv): 8 switches, 2 per Access NDG, location
# from the device's site type (regional/branch). hq/dc have no tagged sites.
# Push the sample: TF_VAR_nad_count=8 (and TF_VAR_nad_tacacs_secret from env).
resource "ise_network_device" "sample" {
  count = var.nad_count

  name                            = local.sample_nads[count.index].hostname
  description                     = "${local.sample_nads[count.index].site_name} access switch"
  authentication_network_protocol = "TACACS_PLUS"
  tacacs_shared_secret            = var.nad_tacacs_secret
  tacacs_connect_mode_options     = "OFF"
  profile_name                    = "Cisco"
  network_device_groups = [
    ise_network_device_group.ndg[local.sample_nads[count.index].access_ndg].name,
    ise_network_device_group.location[local.sample_nads[count.index].location_type].name,
  ]

  ips = [
    {
      ipaddress = split("/", local.sample_nads[count.index].mgmt_ip)[0]
      mask      = split("/", local.sample_nads[count.index].mgmt_ip)[1]
    }
  ]

  lifecycle {
    precondition {
      condition     = var.nad_count <= length(local.sample_nads)
      error_message = "nad_count cannot exceed the curated sample (${length(local.sample_nads)}). Default 0. Sample is TF_VAR_nad_count=8."
    }
    precondition {
      condition     = var.nad_count == 0 || length(var.nad_tacacs_secret) > 0
      error_message = "Set TF_VAR_nad_tacacs_secret (or NAD_TACACS_SECRET in .env) before pushing sample NADs. Do not put the secret in git."
    }
  }
}
