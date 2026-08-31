# Optional sample NADs. Default count is 0 so first apply does not push 6250 devices.
resource "ise_network_device" "sample" {
  count = var.nad_count

  name                            = local.devices[count.index].hostname
  description                     = "${local.devices[count.index].site_name} access switch"
  authentication_network_protocol = "TACACS_PLUS"
  tacacs_shared_secret            = var.nad_tacacs_secret
  tacacs_connect_mode_options     = "OFF"
  profile_name                    = "Cisco"
  network_device_groups = [
    ise_network_device_group.ndg["access-marketing"].name,
  ]

  ips = [
    {
      ipaddress = split("/", local.devices[count.index].mgmt_ip)[0]
      mask      = split("/", local.devices[count.index].mgmt_ip)[1]
    }
  ]
}
