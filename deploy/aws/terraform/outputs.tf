output "load_balancer_dns_name" {
  value = aws_lb.main.dns_name
}

output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.main.arn
}

output "service_arn" {
  value = aws_ecs_service.main.id
}

output "configured_image" {
  value = var.image
}

output "cloudwatch_log_group" {
  value = aws_cloudwatch_log_group.main.name
}

output "private_subnet_ids" {
  value = [for subnet in aws_subnet.private : subnet.id]
}

output "task_security_group_id" {
  value = aws_security_group.tasks.id
}

output "admin_bootstrap_secret_arn" {
  value = aws_secretsmanager_secret.admin_bootstrap.arn
}

output "configured_steady_state_application_database_connections" {
  description = "Configured steady-state aggregate application connection ceiling across maximum_tasks ECS tasks; completion connections are included, not added. Rollout and provider overshoot are excluded."
  value       = var.maximum_tasks * var.db_connections_per_task
}

output "configured_steady_state_regular_application_database_connections" {
  description = "Configured steady-state regular-work connection ceiling across maximum_tasks ECS tasks. Rollout and provider overshoot are excluded."
  value       = var.maximum_tasks * (var.db_connections_per_task - var.db_completion_connections_per_task)
}

output "configured_steady_state_completion_application_database_connections" {
  description = "Configured steady-state completion-reserved connection ceiling across maximum_tasks ECS tasks; this is already included in configured_steady_state_application_database_connections. Rollout and provider overshoot are excluded."
  value       = var.maximum_tasks * var.db_completion_connections_per_task
}

output "maximum_application_database_connections" {
  description = "Compatibility alias for configured_steady_state_application_database_connections. Despite the legacy maximum name, rollout and provider overshoot are excluded."
  value       = var.maximum_tasks * var.db_connections_per_task
}

output "maximum_regular_application_database_connections" {
  description = "Compatibility alias for configured_steady_state_regular_application_database_connections. Despite the legacy maximum name, rollout and provider overshoot are excluded."
  value       = var.maximum_tasks * (var.db_connections_per_task - var.db_completion_connections_per_task)
}

output "maximum_completion_application_database_connections" {
  description = "Compatibility alias for configured_steady_state_completion_application_database_connections. Despite the legacy maximum name, rollout and provider overshoot are excluded."
  value       = var.maximum_tasks * var.db_completion_connections_per_task
}
