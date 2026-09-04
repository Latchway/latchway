data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)
  vpc_cidr           = "10.30.0.0/16"
  dns_resolver_cidr  = "${cidrhost(local.vpc_cidr, 2)}/32"

  runtime_secrets = concat(
    [
      {
        name      = "LATCHWAY_DATABASE_URL"
        valueFrom = aws_secretsmanager_secret.database_url.arn
      },
      {
        name      = "LATCHWAY_MASTER_KEY"
        valueFrom = aws_secretsmanager_secret.master_key.arn
      },
    ],
    var.inject_admin_bootstrap_token ? [
      {
        name      = "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN"
        valueFrom = aws_secretsmanager_secret.admin_bootstrap.arn
      },
    ] : [],
  )
}

resource "aws_vpc" "main" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "public" {
  for_each = toset(local.availability_zones)

  vpc_id                  = aws_vpc.main.id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(local.vpc_cidr, 8, index(local.availability_zones, each.key))
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-public-${each.key}" }
}

resource "aws_subnet" "private" {
  for_each = toset(local.availability_zones)

  vpc_id            = aws_vpc.main.id
  availability_zone = each.key
  cidr_block        = cidrsubnet(local.vpc_cidr, 8, 10 + index(local.availability_zones, each.key))

  tags = { Name = "${var.name}-private-${each.key}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  domain = "vpc"

  depends_on = [aws_internet_gateway.main]
  tags       = { Name = "${var.name}-nat" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[local.availability_zones[0]].id

  depends_on = [aws_internet_gateway.main]
  tags       = { Name = "${var.name}-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = { Name = "${var.name}-private" }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "load_balancer" {
  name        = "${var.name}-alb"
  description = "Public HTTPS ingress to Latchway"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Latchway target port inside the VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
}

# Provider APIs and customer-configured upstreams use HTTPS and may publish
# dynamic addresses, so a static destination allowlist is not generally safe.
# trivy:ignore:AWS-0104
resource "aws_security_group" "tasks" {
  name        = "${var.name}-tasks"
  description = "Only the ALB may reach Latchway tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
  }

  egress {
    description = "TLS to provider APIs and AWS service endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "PostgreSQL inside the VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  egress {
    description = "UDP DNS to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [local.dns_resolver_cidr]
  }

  egress {
    description = "TCP DNS fallback to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [local.dns_resolver_cidr]
  }
}

resource "aws_security_group" "database" {
  name        = "${var.name}-database"
  description = "PostgreSQL from Latchway tasks only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.tasks.id]
  }
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

resource "aws_db_subnet_group" "main" {
  name       = var.name
  subnet_ids = [for subnet in aws_subnet.private : subnet.id]
}

resource "aws_db_parameter_group" "main" {
  name   = "${var.name}-postgres18"
  family = "postgres18"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "main" {
  identifier = "${var.name}-postgres"

  engine         = "postgres"
  engine_version = "18"
  instance_class = var.database_instance_class

  db_name  = var.database_name
  username = var.database_user
  password = random_password.database.result
  port     = 5432

  allocated_storage     = 50
  max_allocated_storage = 500
  storage_type          = "gp3"
  storage_encrypted     = true

  multi_az               = var.database_multi_az
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  parameter_group_name   = aws_db_parameter_group.main.name

  backup_retention_period = 7
  backup_window           = "02:00-03:00"
  maintenance_window      = "sun:03:30-sun:04:30"
  copy_tags_to_snapshot   = true

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  auto_minor_version_upgrade            = true

  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final-snapshot"
}

resource "aws_secretsmanager_secret" "database_url" {
  name                    = "${var.name}/database-url"
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = format(
    "postgresql://%s:%s@%s:5432/%s?sslmode=require",
    urlencode(var.database_user),
    urlencode(random_password.database.result),
    aws_db_instance.main.address,
    urlencode(var.database_name),
  )
}

resource "aws_secretsmanager_secret" "master_key" {
  name                    = "${var.name}/master-key"
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "master_key" {
  secret_id     = aws_secretsmanager_secret.master_key.id
  secret_string = random_id.master_key.b64_std
}

resource "aws_secretsmanager_secret" "admin_bootstrap" {
  name                    = "${var.name}/admin-bootstrap-token"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "admin_bootstrap" {
  secret_id     = aws_secretsmanager_secret.admin_bootstrap.id
  secret_string = random_password.admin_bootstrap.result
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = concat(
      [
        aws_secretsmanager_secret.database_url.arn,
        aws_secretsmanager_secret.master_key.arn,
      ],
      var.inject_admin_bootstrap_token ? [aws_secretsmanager_secret.admin_bootstrap.arn] : [],
    )
  }
}

resource "aws_iam_role_policy" "secrets" {
  name   = "${var.name}-runtime-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.secrets.json
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_cloudwatch_log_group" "main" {
  name              = "/ecs/${var.name}"
  retention_in_days = 30
}

resource "aws_ecs_cluster" "main" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "main" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "2048"
  memory                   = "4096"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "latchway"
      image     = var.image
      essential = true
      user      = "65532"
      command   = ["serve", "--role", "all"]

      readonlyRootFilesystem = true
      stopTimeout            = 35
      linuxParameters = {
        initProcessEnabled = true
        capabilities = {
          drop = ["ALL"]
        }
      }

      portMappings = [
        {
          name          = "http1"
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
          appProtocol   = "http"
        },
      ]

      environment = [
        { name = "PORT", value = "8080" },
        { name = "LATCHWAY_ROLE", value = "all" },
        { name = "LATCHWAY_LOG_LEVEL", value = "info" },
        { name = "LATCHWAY_MIGRATE_ON_START", value = tostring(var.migrate_on_start) },
        { name = "LATCHWAY_DB_MAX_CONNECTIONS", value = tostring(var.db_connections_per_task) },
        { name = "LATCHWAY_DB_COMPLETION_CONNECTIONS", value = tostring(var.db_completion_connections_per_task) },
        { name = "LATCHWAY_PUBLIC_ORIGIN", value = var.public_origin },
        { name = "LATCHWAY_SHUTDOWN_TIMEOUT", value = "30s" },
      ]
      secrets = local.runtime_secrets

      healthCheck = {
        command     = ["CMD", "/latchway", "--server", "http://127.0.0.1:8080", "--output", "json", "readiness"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.main.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "latchway"
        }
      }
    },
  ])

  depends_on = [aws_iam_role_policy.secrets]

  lifecycle {
    precondition {
      condition     = var.db_completion_connections_per_task < var.db_connections_per_task
      error_message = "db_completion_connections_per_task must be less than the aggregate db_connections_per_task budget."
    }
  }
}

# This is intentionally the public HTTPS entry point. Tasks and PostgreSQL
# remain private and accept traffic only through their security-group chain.
# trivy:ignore:AWS-0053
resource "aws_lb" "main" {
  name               = var.name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = [for subnet in aws_subnet.public : subnet.id]

  enable_deletion_protection = true
  enable_http2               = true
  drop_invalid_header_fields = true
  idle_timeout               = 4000
}

resource "aws_lb_target_group" "main" {
  name        = var.name
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  deregistration_delay = 60

  health_check {
    enabled             = true
    path                = "/readyz"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

resource "aws_ecs_service" "main" {
  name                  = var.name
  cluster               = aws_ecs_cluster.main.id
  task_definition       = aws_ecs_task_definition.main.arn
  desired_count         = var.desired_tasks
  launch_type           = "FARGATE"
  wait_for_steady_state = true

  enable_execute_command             = false
  health_check_grace_period_seconds  = 120
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    subnets          = [for subnet in aws_subnet.private : subnet.id]
    security_groups  = [aws_security_group.tasks.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.main.arn
    container_name   = "latchway"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_appautoscaling_target" "service" {
  max_capacity       = var.maximum_tasks
  min_capacity       = var.minimum_tasks
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.service.resource_id
  scalable_dimension = aws_appautoscaling_target.service.scalable_dimension
  service_namespace  = aws_appautoscaling_target.service.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
