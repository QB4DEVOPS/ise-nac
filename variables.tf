variable "ise_host" {
  type        = string
  description = "PAN IP or hostname. Same as ISE_HOST in .env."
  default     = "192.168.1.90"
}

variable "ise_username" {
  type        = string
  description = "ISE admin user. Same as ISE_USERNAME in .env."
  default     = "iseadmin"
}

variable "nad_count" {
  type        = number
  description = "How many devices.csv NADs to push (first N, inventory order). Default 15000 = all access switches. Set TF_VAR_nad_count=0 for policy-only (Location tree + TACACS + wired 802.1X/MAB, no switches)."
  default     = 15000

  validation {
    condition     = var.nad_count >= 0 && var.nad_count <= 15000
    error_message = "nad_count must be 0 (policy-only, no NADs) through 15000 (all devices.csv rows, the default). Policy-only is TF_VAR_nad_count=0."
  }
}

variable "nad_tacacs_secret" {
  type        = string
  sensitive   = true
  default     = ""
  description = "TACACS shared secret for NADs. Set via TF_VAR_nad_tacacs_secret or NAD_TACACS_SECRET in .env. Never commit a real secret."
}

variable "nad_radius_secret" {
  type        = string
  sensitive   = true
  default     = ""
  description = "RADIUS shared secret for NADs (802.1X/MAB). Set via TF_VAR_nad_radius_secret or NAD_RADIUS_SECRET in .env. Never commit a real secret."
}

variable "endpoint_count" {
  type        = number
  description = "MAC endpoints to push. Stays 0: endpoint identity groups only. Do not generate a MAC list."
  default     = 0

  validation {
    condition     = var.endpoint_count == 0
    error_message = "endpoint_count stays 0. Workstation / IP-Phone / Printer groups only. Do not generate 300k MACs."
  }
}
