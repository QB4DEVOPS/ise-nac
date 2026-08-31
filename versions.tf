terraform {
  required_version = ">= 1.3.0"

  required_providers {
    # Current Cisco ISE provider (tested with ISE 3.5). Not the older CiscoISE/ciscoise beta.
    ise = {
      source  = "CiscoDevNet/ise"
      version = "~> 0.3.4"
    }
  }
}
