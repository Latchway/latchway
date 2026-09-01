terraform {
  required_version = ">= 1.8.0"

  # Production initialization must provide the GCS bucket and prefix through
  # -backend-config. Static validation intentionally uses -backend=false.
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 8.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6, < 4.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
