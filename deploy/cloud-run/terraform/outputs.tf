output "service_url" {
  value = google_cloud_run_v2_service.main.uri
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
  value = google_secret_manager_secret.admin_bootstrap.secret_id
}

output "service_resource_id" {
  value = google_cloud_run_v2_service.main.id
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

output "maximum_application_database_connections" {
  value = var.max_instances * var.db_connections_per_instance
}
