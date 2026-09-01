# Inventory is devices.csv (15,000 access switches). Default count is 15000 so a
# normal apply pushes every row. Policy-only (no switches): TF_VAR_nad_count=0.
# TACACS secret from TF_VAR_nad_tacacs_secret / NAD_TACACS_SECRET (env only).
# RADIUS secret from TF_VAR_nad_radius_secret / NAD_RADIUS_SECRET (env only).
# ISE still requires authenticationSettings.radiusSharedSecret for TACACS_PLUS NADs.
# Provider field (CiscoDevNet/ise 0.3.4): authentication_radius_shared_secret.
# Protocol stays TACACS_PLUS. sample_nads.csv is an optional 8-row reference
# slice; nad_count does not read it.
#
# Each NAD joins exactly two groups:
#   Access:   access-marketing (CoS lock until Robert tags Access)
#   Location: the state/city path — Location#All Locations#{State}#{site_id}
# NADs do not join type-level regional/branch/hq/dc as their Location parent.
resource "ise_network_device" "nad" {
  count = var.nad_count

  name                                = local.devices[count.index].hostname
  description                         = "${local.devices[count.index].site_name} access switch"
  authentication_network_protocol     = "TACACS_PLUS"
  tacacs_shared_secret                = var.nad_tacacs_secret
  authentication_radius_shared_secret = var.nad_radius_secret
  tacacs_connect_mode_options         = "OFF"
  profile_name                        = "Cisco"
  network_device_groups = [
    ise_network_device_group.ndg[local.default_access_ndg].name,
    ise_network_device_group.site_location[local.devices[count.index].site_code].name,
  ]

  ips = [
    {
      ipaddress = split("/", local.devices[count.index].mgmt_ip)[0]
      mask      = split("/", local.devices[count.index].mgmt_ip)[1]
    }
  ]

  lifecycle {
    precondition {
      condition     = contains([for row in local.ndgs : row.ndg], local.default_access_ndg)
      error_message = "Locked Access NDG '${local.default_access_ndg}' is missing from ndgs.csv."
    }
    precondition {
      condition     = var.nad_count <= length(local.devices)
      error_message = "nad_count cannot exceed devices.csv (${length(local.devices)}). Default is all ${length(local.devices)} rows. Policy-only is TF_VAR_nad_count=0."
    }
    precondition {
      condition     = var.nad_count == 0 || length(var.nad_tacacs_secret) > 0
      error_message = "Set TF_VAR_nad_tacacs_secret (or NAD_TACACS_SECRET in .env) before pushing NADs. Do not put the secret in git."
    }
    precondition {
      condition     = var.nad_count == 0 || length(var.nad_radius_secret) > 0
      error_message = "Set TF_VAR_nad_radius_secret (or NAD_RADIUS_SECRET in .env) before pushing NADs. ISE requires a RADIUS shared secret even for TACACS_PLUS devices. Do not put the secret in git."
    }
  }
}
