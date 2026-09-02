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
  description = "How many endpoints.csv lab MACs to push (first N, inventory order). Default 110 = all 11 groups × 10. Set TF_VAR_endpoint_count=0 for groups-only (no MAC rows). Do not dump 15k MACs. endpoints_enterprise.csv (150k desks/phone+PC) is Git inventory only — pan1 apply stays 110 until Robert says so."
  default     = 110

  validation {
    condition     = var.endpoint_count >= 0 && var.endpoint_count <= 110
    error_message = "endpoint_count must be 0 (groups only, no MACs) through 110 (all endpoints.csv lab MACs, the default). Groups-only is TF_VAR_endpoint_count=0. Do not dump 15k MACs."
  }
}

variable "user_count" {
  type        = number
  description = "How many users.csv lab Internal Users to push (first N, inventory order). Default 8 = one per TACACS identity group (T1–T4, vendor, contractor, auditor-internal, auditor-external). Set TF_VAR_user_count=0 to skip user rows (identity groups still apply). Do not dump 150k users."
  default     = 8

  validation {
    condition     = var.user_count >= 0 && var.user_count <= 8
    error_message = "user_count must be 0 (no Internal User rows) through 8 (all users.csv lab users, the default). Skip users with TF_VAR_user_count=0. Do not dump 150k users."
  }
}

variable "user_password" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Login password for Internal Users (ise_internal_user.password). Set via TF_VAR_user_password or USER_PASSWORD_DEFAULT in .env. Required when user_count>0. Never commit a real secret."
}

variable "user_enable_password" {
  type        = string
  sensitive   = true
  default     = ""
  description = "TACACS enable password for Internal Users (ise_internal_user.enable_password). Set via TF_VAR_user_enable_password or USER_ENABLE_PASSWORD_DEFAULT in .env. Empty reuses user_password. Never commit a real secret."
}
