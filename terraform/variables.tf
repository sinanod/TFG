variable "location" {
  description = "The Azure region to deploy resources in."
  type        = string
  default     = "North Europe"  # Cambia según tu preferencia
}

variable "admin_username" {
  description = "The admin username for the Linux VM."
  type        = string
}

variable "admin_password" {
  description = "The admin password for the Linux VM."
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "The public SSH key for the Linux VM."
  type        = string
}

variable "subscription_id" {
  type        = string
  description = "The subscription ID for Azure."
}

variable "client_id" {
  type        = string
  description = "The client ID for the Azure service principal."
}

variable "client_secret" {
  type        = string
  description = "The client secret for the Azure service principal."
  sensitive   = true
}

variable "tenant_id" {
  type        = string
  description = "The tenant ID for Azure."
}
