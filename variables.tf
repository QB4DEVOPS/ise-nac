variable "ise_host" {
  type        = string
  description = "PAN IP or hostname. Same as ISE_HOST in .env."
  default     = "192.168.1.90"
}

variable "ise_username" {
  type        = string
  description = "ISE admin user. Same as ISE_USERNAME in .env."
  default     = "admin"
}

variable "nad_count" {
  type        = number
  description = "How many NADs to push from devices.csv. 0 = none (first apply). 2 = tiny sample. Will not push 6250."
  default     = 0

  validation {
    condition     = var.nad_count >= 0 && var.nad_count <= 2
    error_message = "nad_count must be 0 (default, no NADs) or 1–2 (tiny sample). This repo will not push 6250 NADs."
  }
}

variable "nad_tacacs_secret" {
  type        = string
  sensitive   = true
  description = "Placeholder TACACS secret for the optional sample NADs only. Not the lab admin password."
  default     = "changeme"
}
