variable "project_id" {
  description = "Google Cloud project that owns the deployment."
  type        = string
}

variable "region" {
  description = "Cloud Run, VPC, and Cloud SQL region."
  type        = string
  default     = "asia-southeast1"
}

variable "service_name" {
  description = "Cloud Run service and related resource prefix."
  type        = string
  default     = "latchway"
}

variable "image" {
  description = "Verified OCI image by digest, for example ghcr.io/latchway/latchway@sha256:..."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be immutable and end in an OCI sha256 digest."
  }
}

variable "public_origin" {
  description = "Final public HTTPS origin with no path, query, or fragment."
  type        = string

  validation {
    condition     = can(regex("^https://[^/?#]+$", var.public_origin))
    error_message = "public_origin must be an HTTPS origin without path, query, or fragment."
  }
}

variable "database_name" {
  type    = string
  default = "latchway"
}

variable "database_user" {
  type    = string
  default = "latchway"
}

variable "database_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-2-7680"
}

variable "database_availability_type" {
  description = "Use REGIONAL for HA production and ZONAL only for evaluation."
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["REGIONAL", "ZONAL"], var.database_availability_type)
    error_message = "database_availability_type must be REGIONAL or ZONAL."
  }
}

variable "min_instances" {
  type    = number
  default = 1
}

variable "max_instances" {
  type    = number
  default = 10
}

variable "db_connections_per_instance" {
  description = "Latchway pool size per Cloud Run instance."
  type        = number
  default     = 20

  validation {
    condition     = var.db_connections_per_instance >= 2 && var.db_connections_per_instance <= 100
    error_message = "db_connections_per_instance must be between 2 and 100."
  }
}

variable "allow_unauthenticated" {
  description = "Expose Cloud Run publicly; Latchway still enforces its own DPoP/session security."
  type        = bool
  default     = true
}
