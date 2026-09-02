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

variable "service_image" {
  description = "Verified OCI image digest served to application traffic. Keep the old digest here until the new migration image has run successfully."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.service_image))
    error_message = "service_image must be immutable and end in an OCI sha256 digest."
  }
}

variable "migration_image" {
  description = "Verified OCI image digest used by the one-shot migration job. Advance this before service_image during an upgrade."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.migration_image))
    error_message = "migration_image must be immutable and end in an OCI sha256 digest."
  }
}

variable "migration_approved_service_image" {
  description = "Exact service digest whose migrations the operator has verified. It must equal service_image before Terraform can create or route to that revision."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.migration_approved_service_image))
    error_message = "migration_approved_service_image must be immutable and end in an OCI sha256 digest."
  }
}

variable "service_revision_name" {
  description = "Explicit Cloud Run revision name for service_image; use a new immutable name for each digest."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", var.service_revision_name))
    error_message = "service_revision_name must be a 2-63 character lowercase Cloud Run revision name."
  }
}

variable "previous_service_revision_name" {
  description = "Revision retaining traffic while a new candidate is created at 0 percent. Set null for the first deployment or after full promotion."
  type        = string
  default     = null

  validation {
    condition = (
      var.previous_service_revision_name == null ||
      can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", var.previous_service_revision_name))
    )
    error_message = "previous_service_revision_name must be null or a valid lowercase Cloud Run revision name."
  }
}

variable "service_traffic_percent" {
  description = "Traffic assigned to service_revision_name. Use 0 for the probe phase and 100 only after readiness succeeds."
  type        = number
  default     = 100

  validation {
    condition     = var.service_traffic_percent >= 0 && var.service_traffic_percent <= 100 && floor(var.service_traffic_percent) == var.service_traffic_percent
    error_message = "service_traffic_percent must be an integer from 0 through 100."
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

variable "database_edition" {
  description = "Cloud SQL edition. PostgreSQL 18 with the db-custom tier requires Enterprise."
  type        = string
  default     = "ENTERPRISE"

  validation {
    condition     = var.database_edition == "ENTERPRISE"
    error_message = "database_edition must be ENTERPRISE while database_tier uses db-custom."
  }
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

variable "inject_admin_bootstrap_token" {
  description = "Inject the generated bootstrap token. Set false immediately after the first administrator is created."
  type        = bool
  default     = true
}

variable "migrate_on_start" {
  description = "Safe first-deploy fallback; set false after adopting the explicit migration-job workflow."
  type        = bool
  default     = true
}
