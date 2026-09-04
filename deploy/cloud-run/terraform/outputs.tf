output "service_url" {
  value = try(google_cloud_run_v2_service.main[0].uri, null)
}

output "migration_command" {
  value = "gcloud run jobs execute ${google_cloud_run_v2_job.migrate.name} --region ${var.region} --wait"
}

output "database_url_secret" {
  value = google_secret_manager_secret.database_url.secret_id
}

output "master_key_secret" {
  value = google_secret_manager_secret.master_key.secret_id
}

output "admin_bootstrap_secret" {
  description = "Temporary setup secret resource. It is not injected or readable by the runtime in the default steady-state profile."
  value = google_secret_manager_secret.admin_bootstrap.secret_id
}

output "runtime_service_account" {
  value = google_service_account.runtime.email
}

output "migrator_service_account" {
  value = google_service_account.migrator.email
}

output "service_resource_id" {
  value = try(google_cloud_run_v2_service.main[0].id, null)
}

output "migration_job_resource_id" {
  value = google_cloud_run_v2_job.migrate.id
}

output "configured_image" {
  description = "Compatibility alias for the application service image."
  value       = var.service_image
}

output "configured_service_image" {
  value = var.service_image
}

output "configured_migration_image" {
  value = var.migration_image
}

output "configured_service_revision" {
  value = var.service_revision_name
}

output "configured_previous_service_revision" {
  value = var.previous_service_revision_name
}

output "configured_service_traffic_percent" {
  value = var.service_traffic_percent
}

output "configured_steady_state_application_database_connections" {
  description = "Configured steady-state aggregate application connection ceiling across max_instances Cloud Run service instances; completion connections are included, not added. Rollout and provider overshoot are excluded."
  value       = var.max_instances * var.db_connections_per_instance
}

output "configured_steady_state_regular_application_database_connections" {
  description = "Configured steady-state regular-work connection ceiling across max_instances Cloud Run service instances. Rollout and provider overshoot are excluded."
  value       = var.max_instances * (var.db_connections_per_instance - var.db_completion_connections_per_instance)
}

output "configured_steady_state_completion_application_database_connections" {
  description = "Configured steady-state completion-reserved connection ceiling across max_instances Cloud Run service instances; this is already included in configured_steady_state_application_database_connections. Rollout and provider overshoot are excluded."
  value       = var.max_instances * var.db_completion_connections_per_instance
}

output "maximum_application_database_connections" {
  description = "Compatibility alias for configured_steady_state_application_database_connections. Despite the legacy maximum name, rollout and provider overshoot are excluded."
  value       = var.max_instances * var.db_connections_per_instance
}

output "maximum_regular_application_database_connections" {
  description = "Compatibility alias for configured_steady_state_regular_application_database_connections. Despite the legacy maximum name, rollout and provider overshoot are excluded."
  value       = var.max_instances * (var.db_connections_per_instance - var.db_completion_connections_per_instance)
}

output "maximum_completion_application_database_connections" {
  description = "Compatibility alias for configured_steady_state_completion_application_database_connections. Despite the legacy maximum name, rollout and provider overshoot are excluded."
  value       = var.max_instances * var.db_completion_connections_per_instance
}
