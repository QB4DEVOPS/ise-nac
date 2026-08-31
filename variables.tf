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
  description = "How many curated sample NADs to push (sample_nads.csv). 0 = none (default). 8 = full sample (2 per Access NDG). Will not push 6250."
  default     = 0

  validation {
    condition     = var.nad_count >= 0 && var.nad_count <= 8
    error_message = "nad_count must be 0 (default, no NADs) or 1–8 (curated sample). This repo will not push 6250 NADs. Use TF_VAR_nad_count=8 for the full sample."
  }
}

variable "nad_tacacs_secret" {
  type        = string
  sensitive   = true
  default     = ""
  description = "TACACS shared secret for sample NADs. Set via TF_VAR_nad_tacacs_secret or NAD_TACACS_SECRET in .env. Never commit a real secret."
}
