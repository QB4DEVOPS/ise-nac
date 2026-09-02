# Lab Internal Users from users.csv. Default user_count=8 (all 8 TACACS groups).
# Users-only skip (identity groups still apply): TF_VAR_user_count=0.
# Do not dump 150k. ISE Internal User store max is 300,000; ERS POSTs one user
# per request (ise_internal_user count = one POST each).
#
# CiscoDevNet/ise 0.3.4 resource is ise_internal_user (not ise_user).
# Schema (verified, not invented):
#   name, password, enable_password, change_password, enabled,
#   first_name, last_name, email, description, identity_groups,
#   password_id_store, password_never_expires
# identity_groups is a comma-separated list of identity group IDs.
# password / enable_password come from env only. Never from Git.
# https://registry.terraform.io/providers/CiscoDevNet/ise/0.3.4/docs/resources/internal_user
# ISE scale: Maximum internal users = 300,000
#   https://www.cisco.com/c/en/us/td/docs/security/ise/performance_and_scalability/b_ise_perf_and_scale.html
# ERS create: POST /ers/config/internaluser (one user per POST)
#   https://developer.cisco.com/docs/identity-services-engine/latest/create-user/

resource "ise_internal_user" "this" {
  count = var.user_count

  name                   = local.users[count.index].username
  password               = var.user_password
  enable_password        = length(var.user_enable_password) > 0 ? var.user_enable_password : var.user_password
  change_password        = false
  enabled                = lower(local.users[count.index].enabled) == "true"
  first_name             = local.users[count.index].first_name
  last_name              = local.users[count.index].last_name
  email                  = local.users[count.index].email
  description            = local.users[count.index].description
  password_id_store      = "Internal Users"
  password_never_expires = true
  identity_groups        = join(",", [for g in split(",", local.users[count.index].identity_group) : ise_user_identity_group.this[trimspace(g)].id])

  lifecycle {
    precondition {
      condition     = var.user_count <= length(local.users)
      error_message = "user_count cannot exceed users.csv (${length(local.users)}). Default is all ${length(local.users)} lab Internal Users. Skip users with TF_VAR_user_count=0."
    }
    precondition {
      condition     = var.user_count == 0 || length(var.user_password) > 0
      error_message = "Set TF_VAR_user_password (or USER_PASSWORD_DEFAULT in .env) before pushing Internal Users. Do not put the secret in git."
    }
  }
}
