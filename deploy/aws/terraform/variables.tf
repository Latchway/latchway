variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "name" {
  type    = string
  default = "latchway"
}

variable "image" {
  description = "Verified OCI image by digest. Mirror it into ECR for private production pulls."
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

variable "certificate_arn" {
  description = "ACM certificate for the public Latchway origin."
  type        = string
}

variable "desired_tasks" {
  type    = number
  default = 2
}

variable "minimum_tasks" {
  type    = number
  default = 2
}

variable "maximum_tasks" {
  type    = number
  default = 10
}

variable "db_connections_per_task" {
  type    = number
  default = 20

  validation {
    condition     = var.db_connections_per_task >= 2 && var.db_connections_per_task <= 100
    error_message = "db_connections_per_task must be between 2 and 100."
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

variable "database_instance_class" {
  type    = string
  default = "db.r7g.large"
}

variable "database_multi_az" {
  type    = bool
  default = true
}

variable "inject_admin_bootstrap_token" {
  description = "Inject the generated bootstrap token. Set false immediately after the first admin is created."
  type        = bool
  default     = true
}

variable "migrate_on_start" {
  description = "Safe first-deploy fallback; set false after adopting the explicit migration task workflow."
  type        = bool
  default     = true
}
