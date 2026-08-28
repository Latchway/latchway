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

output "maximum_application_database_connections" {
  value = var.max_instances * var.db_connections_per_instance
}
