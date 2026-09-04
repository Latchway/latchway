locals {
  required_apis = toset([
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
    "vpcaccess.googleapis.com",
  ])
}

resource "google_project_service" "required" {
  for_each = local.required_apis
  project  = var.project_id
  service  = each.value

  disable_on_destroy = false
}

resource "google_compute_network" "main" {
  name                    = "${var.service_name}-network"
  auto_create_subnetworks = false

  depends_on = [google_project_service.required]
}

resource "google_vpc_access_connector" "main" {
  name          = "${var.service_name}-connector"
  region        = var.region
  network       = google_compute_network.main.name
  ip_cidr_range = "10.20.0.0/28"
  min_instances = 2
  max_instances = 3

  depends_on = [google_project_service.required]
}

resource "google_compute_global_address" "private_services" {
  name          = "${var.service_name}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]

  depends_on = [google_project_service.required]
}

resource "random_password" "database" {
  length  = 40
  special = false
}

resource "random_id" "master_key" {
  byte_length = 32
}

resource "random_password" "admin_bootstrap" {
  length  = 48
  special = false
}

resource "google_sql_database_instance" "main" {
  name             = "${var.service_name}-postgres"
  region           = var.region
  database_version = "POSTGRES_18"

  deletion_protection = true

  settings {
    edition           = var.database_edition
    tier              = var.database_tier
    availability_type = var.database_availability_type
    disk_type         = "PD_SSD"
    disk_size         = 20
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.main.id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }

    maintenance_window {
      day          = 7
      hour         = 4
      update_track = "stable"
    }
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "main" {
  name     = var.database_name
  instance = google_sql_database_instance.main.name
}

resource "google_sql_user" "main" {
  name     = var.database_user
  instance = google_sql_database_instance.main.name
  password = random_password.database.result
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "${var.service_name}-database-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.database_url.id
  secret_data = format(
    "postgresql://%s:%s@/%s?host=%s&sslmode=disable",
    urlencode(var.database_user),
    urlencode(random_password.database.result),
    urlencode(var.database_name),
    urlencode("/cloudsql/${google_sql_database_instance.main.connection_name}"),
  )
}

resource "google_secret_manager_secret" "master_key" {
  secret_id = "${var.service_name}-master-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "master_key" {
  secret      = google_secret_manager_secret.master_key.id
  secret_data = random_id.master_key.b64_std
}

resource "google_secret_manager_secret" "admin_bootstrap" {
  secret_id = "${var.service_name}-admin-bootstrap-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "admin_bootstrap" {
  secret      = google_secret_manager_secret.admin_bootstrap.id
  secret_data = random_password.admin_bootstrap.result
}

resource "google_service_account" "runtime" {
  account_id   = "${var.service_name}-runtime"
  display_name = "Latchway Cloud Run runtime"

  depends_on = [google_project_service.required]
}

resource "google_service_account" "migrator" {
  account_id   = "${var.service_name}-migrator"
  display_name = "Latchway Cloud Run migration job"

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "runtime_cloud_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "migrator_cloud_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.migrator.email}"
}

resource "google_secret_manager_secret_iam_member" "runtime_database" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.database_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "runtime_master_key" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.master_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "runtime_bootstrap" {
  count = var.inject_admin_bootstrap_token ? 1 : 0

  project   = var.project_id
  secret_id = google_secret_manager_secret.admin_bootstrap.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "migrator_database" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.database_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.migrator.email}"
}

resource "google_cloud_run_v2_service" "main" {
  count = var.deploy_service ? 1 : 0

  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  deletion_protection = false

  template {
    revision                         = var.service_revision_name
    service_account                  = google_service_account.runtime.email
    timeout                          = "3600s"
    max_instance_request_concurrency = 100
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    containers {
      name    = "latchway"
      image   = var.service_image
      command = ["/latchway"]
      args    = ["serve", "--role", "all"]

      ports {
        name           = "http1"
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      env {
        name  = "LATCHWAY_ROLE"
        value = "all"
      }
      env {
        name  = "LATCHWAY_LOG_LEVEL"
        value = "info"
      }
      env {
        name  = "LATCHWAY_MIGRATE_ON_START"
        value = tostring(var.migrate_on_start)
      }
      env {
        name  = "LATCHWAY_PUBLIC_ORIGIN"
        value = var.public_origin
      }
      env {
        name = "LATCHWAY_DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = google_secret_manager_secret_version.database_url.version
          }
        }
      }
      env {
        name = "LATCHWAY_MASTER_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.master_key.secret_id
            version = google_secret_manager_secret_version.master_key.version
          }
        }
      }
      dynamic "env" {
        for_each = var.inject_admin_bootstrap_token ? [1] : []
        content {
          name = "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.admin_bootstrap.secret_id
              version = google_secret_manager_secret_version.admin_bootstrap.version
            }
          }
        }
      }
      env {
        name  = "LATCHWAY_SHUTDOWN_TIMEOUT"
        value = "8s"
      }
      env {
        name  = "LATCHWAY_DB_MAX_CONNECTIONS"
        value = tostring(var.db_connections_per_instance)
      }
      env {
        name  = "LATCHWAY_DB_COMPLETION_CONNECTIONS"
        value = tostring(var.db_completion_connections_per_instance)
      }
      startup_probe {
        initial_delay_seconds = 1
        timeout_seconds       = 3
        period_seconds        = 3
        failure_threshold     = 40
        http_get {
          path = "/readyz"
          port = 8080
        }
      }

      liveness_probe {
        timeout_seconds   = 3
        period_seconds    = 15
        failure_threshold = 3
        http_get {
          path = "/healthz"
          port = 8080
        }
      }
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.main.connection_name]
      }
    }
  }

  traffic {
    type     = "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"
    revision = var.service_revision_name
    percent  = var.service_traffic_percent
    tag      = "candidate"
  }

  dynamic "traffic" {
    for_each = var.previous_service_revision_name != null && var.service_traffic_percent < 100 ? [var.previous_service_revision_name] : []
    content {
      type     = "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"
      revision = traffic.value
      percent  = 100 - var.service_traffic_percent
    }
  }

  depends_on = [
    google_project_iam_member.runtime_cloud_sql_client,
    google_secret_manager_secret_iam_member.runtime_database,
    google_secret_manager_secret_iam_member.runtime_master_key,
    google_secret_manager_secret_iam_member.runtime_bootstrap,
  ]

  lifecycle {
    precondition {
      condition     = var.db_completion_connections_per_instance < var.db_connections_per_instance
      error_message = "db_completion_connections_per_instance must be less than the aggregate db_connections_per_instance budget."
    }
    precondition {
      condition     = var.service_image == var.migration_approved_service_image
      error_message = "service_image must equal the exact migration_approved_service_image before a revision can be created or receive traffic."
    }
    precondition {
      condition     = startswith(var.service_revision_name, "${var.service_name}-")
      error_message = "service_revision_name must start with the Cloud Run service name and a hyphen."
    }
    precondition {
      condition     = var.previous_service_revision_name != null || var.service_traffic_percent == 100
      error_message = "A candidate below 100 percent requires previous_service_revision_name to retain the remaining traffic."
    }
    precondition {
      condition     = var.previous_service_revision_name == null || var.previous_service_revision_name != var.service_revision_name
      error_message = "The previous and candidate Cloud Run revision names must differ."
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  count = var.deploy_service && var.allow_unauthenticated ? 1 : 0

  project  = var.project_id
  location = google_cloud_run_v2_service.main[0].location
  name     = google_cloud_run_v2_service.main[0].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_job" "migrate" {
  name     = "${var.service_name}-migrate"
  location = var.region

  deletion_protection = false

  template {
    task_count  = 1
    parallelism = 1

    template {
      service_account = google_service_account.migrator.email
      timeout         = "900s"
      max_retries     = 0

      vpc_access {
        connector = google_vpc_access_connector.main.id
        egress    = "PRIVATE_RANGES_ONLY"
      }

      containers {
        name    = "latchway-migrate"
        image   = var.migration_image
        command = ["/latchway"]
        args    = ["migrate", "up"]

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name = "LATCHWAY_DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.database_url.secret_id
              version = google_secret_manager_secret_version.database_url.version
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.main.connection_name]
        }
      }
    }
  }

  depends_on = [
    google_project_iam_member.migrator_cloud_sql_client,
    google_secret_manager_secret_iam_member.migrator_database,
  ]
}
