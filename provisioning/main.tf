terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {
    zitadel = {
      source  = "zitadel/zitadel"
      version = "3.8.6"
    }
  }
  # State contains the OIDC client secret. Kubernetes RBAC protects this Secret.
  backend "kubernetes" {
    namespace     = "authn-system"
    secret_suffix = "zitadel"
  }
}

variable "provisioner_pat_file" { type = string }
variable "domain_key_file" { type = string }
variable "instance_id" { type = string }
variable "admin_email" {
  type = string
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+$", var.admin_email))
    error_message = "Provide the real email address of the initial administrator."
  }
}
variable "admin_password_file" { type = string }

provider "zitadel" {
  domain       = "auth.internal"
  insecure     = false
  access_token = trimspace(file(var.provisioner_pat_file))
}
provider "zitadel" {
  alias    = "system"
  domain   = "auth.internal"
  insecure = false
  system_api {
    user     = "domain-provisioner"
    key_file = var.domain_key_file
  }
}

# Adding a native instance domain also registers the console's callback URLs.
# This is the supported ZITADEL domain mechanism, not a Host-header workaround.
resource "zitadel_instance_custom_domain" "console" {
  provider    = zitadel.system
  instance_id = var.instance_id
  domain      = "zitadel.admin.internal"
  lifecycle { prevent_destroy = true }
}

resource "zitadel_human_user" "administrator" {
  user_name                    = var.admin_email
  email                        = var.admin_email
  first_name                   = "Cluster"
  last_name                    = "Administrator"
  is_email_verified            = true
  initial_password             = trimspace(file(var.admin_password_file))
  initial_skip_password_change = false
  lifecycle { prevent_destroy = true }
}
resource "zitadel_instance_member" "administrator" {
  user_id = zitadel_human_user.administrator.id
  roles   = ["IAM_OWNER"]
  lifecycle { prevent_destroy = true }
}
resource "zitadel_project" "administration" {
  name                   = "Cluster administration"
  project_role_assertion = false
  project_role_check     = false
  has_project_check      = false
  lifecycle { prevent_destroy = true }
}
resource "zitadel_application_oidc" "admin_sso" {
  project_id                  = zitadel_project.administration.id
  name                        = "Administrative browser SSO"
  redirect_uris               = ["https://sso.admin.internal/oauth2/callback"]
  response_types              = ["OIDC_RESPONSE_TYPE_CODE"]
  grant_types                 = ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"]
  app_type                    = "OIDC_APP_TYPE_WEB"
  auth_method_type            = "OIDC_AUTH_METHOD_TYPE_BASIC"
  version                     = "OIDC_VERSION_1_0"
  dev_mode                    = false
  access_token_type           = "OIDC_TOKEN_TYPE_BEARER"
  id_token_userinfo_assertion = true
  id_token_role_assertion     = false
  access_token_role_assertion = false
  lifecycle { prevent_destroy = true }
}
output "oauth2_proxy" {
  sensitive = true
  value = {
    client_id     = zitadel_application_oidc.admin_sso.client_id
    client_secret = zitadel_application_oidc.admin_sso.client_secret
  }
}
output "administrator_subject" {
  value = zitadel_human_user.administrator.id
}
