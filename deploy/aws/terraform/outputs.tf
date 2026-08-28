output "load_balancer_dns_name" {
  value = aws_lb.main.dns_name
}

output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.main.arn
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

output "maximum_application_database_connections" {
  value = var.maximum_tasks * var.db_connections_per_task
}
