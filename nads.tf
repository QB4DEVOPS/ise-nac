# Inventory is devices.csv (6,250 access switches). Default count is 0 so a
# normal apply does not push them. Full push: TF_VAR_nad_count=6250 (and
# TF_VAR_nad_tacacs_secret from env). sample_nads.csv is an optional 8-row
# reference slice only; it is not selected by nad_count.
#
# Each NAD joins exactly two groups:
#   Access:   access-marketing (locked; do not invent hr/ceo/sourcecode tags)
#   Location: the device's nested site NDG
#             Location#All Locations#{region}#{site_id}
# NADs do not join type-level regional/branch/hq/dc as their Location parent.
resource "ise_network_device" "nad" {
  count = var.nad_count

  name                            = local.devices[count.index].hostname
  description                     = "${local.devices[count.index].site_name} access switch"
  authentication_network_protocol = "TACACS_PLUS"
  tacacs_shared_secret            = var.nad_tacacs_secret
  tacacs_connect_mode_options     = "OFF"
  profile_name                    = "Cisco"
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
      error_message = "nad_count cannot exceed devices.csv (${length(local.devices)}). Default 0. Full push is TF_VAR_nad_count=6250."
    }
    precondition {
      condition     = var.nad_count == 0 || length(var.nad_tacacs_secret) > 0
      error_message = "Set TF_VAR_nad_tacacs_secret (or NAD_TACACS_SECRET in .env) before pushing NADs. Do not put the secret in git."
    }
  }
}
