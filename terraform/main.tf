# ─────────────────────────────────────────────────────────────
#  Hotel PII Redaction — AWS Infrastructure (Terraform)
#  Production-ready version
#
#  Resources:
#    - Terraform remote state (S3 + DynamoDB)
#    - KMS key (customer-managed, all buckets)
#    - S3 input / output / token-map (encrypted, access-logged, no public)
#    - ECR repository (immutable tags)
#    - VPC + private subnet + security group (Lambda isolation)
#    - Lambda function (container, DLQ, concurrency limit)
#    - SQS dead-letter queue
#    - IAM role (least-privilege, no PutObjectAcl)
#    - CloudWatch log group + error alarm + SNS topic
# ─────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }

  # Remote state — prevents state loss and enables team use
  # Create this bucket manually ONCE before first terraform init:
  #   aws s3 mb s3://your-company-terraform-state --region us-east-1
  #   aws dynamodb create-table --table-name terraform-locks \
  #     --attribute-definitions AttributeName=LockID,AttributeType=S \
  #     --key-schema AttributeName=LockID,KeyType=HASH \
  #     --billing-mode PAY_PER_REQUEST
  backend "s3" {
    bucket         = "gg-lambda-deployments"
    key            = "gg-encryptionservice/terraform.tfstate"
    region         = "us-east-2"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ─────────────────────────────────────────────────
variable "aws_region"       { default = "us-east-1" }
variable "project_name"     { default = "hotel-pii-redaction" }
variable "environment"      { default = "prod" }
variable "mode"             { default = "tokenize" }
variable "confidence"       { default = "0.6" }
variable "image_tag"        { default = "latest" }      # pin to SHA in CI/CD
variable "max_concurrency"  { default = 10 }            # max parallel Lambda executions
variable "alert_email"      { default = "ops@yourcompany.com" }  # CHANGE THIS
variable "max_file_mb"      { default = "50" }
variable "log_retention_days"      { default = 90 }
variable "provisioned_concurrency"  { default = 0 }   # set to 1 to keep Lambda warm

# Input bucket where hotel transcripts are dropped (key pattern: <HotelCode>/YYYY/MM/DD/<Agent>/Audio/*.txt)
variable "input_bucket_name" { default = "gg-transcriptions" }

# Postgres connection (DB must be reachable from the Lambda VPC/subnets)
variable "db_host"     { default = "" }
variable "db_port"     { default = "5432" }
variable "db_name"     { default = "" }
variable "db_user"     { default = "" }
variable "db_password" {
  default   = ""
  sensitive = true
}

locals {
  prefix = "${var.project_name}-${var.environment}"
  tags   = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ════════════════════════════════════════════════════════════
#  KMS KEY  (customer-managed, used for all buckets + Lambda env)
# ════════════════════════════════════════════════════════════

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "kms_policy" {
  # Root account has full access (required — without this, key becomes unmanageable)
  statement {
    sid       = "RootAccess"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  # Lambda role can encrypt/decrypt (needed for S3 SSE-KMS and CloudWatch logs)
  statement {
    sid = "LambdaAccess"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda_role.arn]
    }
  }
  # S3 service needs GenerateDataKey to encrypt objects on behalf of Lambda
  statement {
    sid       = "S3ServiceAccess"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
  # CloudWatch Logs service needs access to encrypt log groups
  statement {
    sid       = "CloudWatchLogsAccess"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "main" {
  description             = "${local.prefix} encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_policy.json
  tags                    = local.tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.prefix}"
  target_key_id = aws_kms_key.main.key_id
}

# ════════════════════════════════════════════════════════════
#  S3 HELPER MODULE (applied to all 3 data buckets)
# ════════════════════════════════════════════════════════════

# ── INPUT BUCKET ─────────────────────────────────────────────
data "aws_s3_bucket" "input" {
  bucket = var.input_bucket_name
}

resource "aws_s3_bucket_versioning" "input" {
  bucket = data.aws_s3_bucket.input.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "input" {
  bucket = data.aws_s3_bucket.input.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "input" {
  bucket                  = data.aws_s3_bucket.input.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── OUTPUT BUCKET ─────────────────────────────────────────────
data "aws_s3_bucket" "output" {
  bucket = "gg-transcriptions-en"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "output" {
  bucket = data.aws_s3_bucket.output.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "output" {
  bucket                  = data.aws_s3_bucket.output.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── TOKEN MAP BUCKET  (most sensitive — separate from redacted files) ─────────
data "aws_s3_bucket" "token_map" {
  bucket = "gg-convert-map"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "token_map" {
  bucket = data.aws_s3_bucket.token_map.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "token_map" {
  bucket                  = data.aws_s3_bucket.token_map.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ════════════════════════════════════════════════════════════
#  ECR REPOSITORY  (immutable tags — no overwriting images)
# ════════════════════════════════════════════════════════════

resource "aws_ecr_repository" "lambda_repo" {
  name                 = local.prefix
  image_tag_mutability = "IMMUTABLE"    # was MUTABLE — changed for prod

  image_scanning_configuration { scan_on_push = true }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.main.arn
  }

  tags = local.tags
}

resource "aws_ecr_lifecycle_policy" "lambda_repo" {
  repository = aws_ecr_repository.lambda_repo.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10 }
      action       = { type = "expire" }
    }]
  })
}

# ════════════════════════════════════════════════════════════
#  VPC  (Lambda runs in private subnet — no internet exposure)
# ════════════════════════════════════════════════════════════

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${local.prefix}-vpc" })
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet("10.0.0.0/16", 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge(local.tags, { Name = "${local.prefix}-private-${count.index}" })
}

data "aws_availability_zones" "available" { state = "available" }

resource "aws_security_group" "lambda_sg" {
  name        = "${local.prefix}-lambda-sg"
  description = "Lambda egress to AWS services via VPC endpoints only"
  vpc_id      = aws_vpc.main.id

  # No inbound — Lambda is triggered by events, not HTTP
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to AWS APIs (via VPC endpoints)"
  }

  tags = local.tags
}

# Security group attached to Interface VPC endpoints — allows the Lambda
# security group to reach the endpoint ENIs on 443.
resource "aws_security_group" "vpce_sg" {
  name        = "${local.prefix}-vpce-sg"
  description = "Allow Lambda SG to reach Interface VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda_sg.id]
    description     = "HTTPS from Lambda"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# ════════════════════════════════════════════════════════════
#  VPC ENDPOINTS  (Lambda has no NAT — must reach AWS via endpoints)
# ════════════════════════════════════════════════════════════

# Route table for private subnets — required for the S3 Gateway endpoint.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.tags, { Name = "${local.prefix}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# S3 — Gateway endpoint (free, attaches to route table)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = local.tags
}

# Interface endpoints — KMS, SQS, CloudWatch Logs.
# (ECR endpoints are NOT needed: Lambda service pulls images, not the function ENI.)
locals {
  interface_endpoints = toset([
    "kms",
    "sqs",
    "logs",
  ])
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpce_sg.id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "${local.prefix}-vpce-${each.key}" })
}

# ════════════════════════════════════════════════════════════
#  SQS DEAD-LETTER QUEUE
# ════════════════════════════════════════════════════════════

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.prefix}-dlq"
  message_retention_seconds = 1209600   # 14 days
  kms_master_key_id         = aws_kms_key.main.arn
  tags                      = local.tags
}

# ════════════════════════════════════════════════════════════
#  IAM ROLE  (least-privilege — no PutObjectAcl)
# ════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "${local.prefix}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "aws_iam_policy_document" "lambda_permissions" {
  # Read input transcripts
  statement {
    sid       = "ReadInput"
    actions   = ["s3:GetObject"]
    resources = ["${data.aws_s3_bucket.input.arn}/*"]
  }
  # Write redacted outputs (no PutObjectAcl)
  statement {
    sid       = "WriteOutput"
    actions   = ["s3:PutObject"]
    resources = [
      "${data.aws_s3_bucket.output.arn}/*",
      "${data.aws_s3_bucket.token_map.arn}/*",
    ]
  }
  # Idempotency check — HeadObject is authorized by s3:GetObject (no separate action exists).
  # With SSE-KMS, HeadObject additionally requires kms:Decrypt on the key (granted below).
  statement {
    sid     = "HeadOutput"
    actions = ["s3:GetObject"]
    resources = [
      "${data.aws_s3_bucket.output.arn}/*",
      "${data.aws_s3_bucket.token_map.arn}/*",
    ]
  }
  # KMS for encrypt/decrypt
  statement {
    sid     = "KMSAccess"
    actions = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
  }
  # DLQ
  statement {
    sid       = "DLQSend"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name   = "permissions"
  role   = aws_iam_role.lambda_role.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# ════════════════════════════════════════════════════════════
#  CLOUDWATCH LOG GROUP
# ════════════════════════════════════════════════════════════

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/gg-encryptionservice"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.main.arn
  tags              = local.tags
}

# ════════════════════════════════════════════════════════════
#  SNS ALERT TOPIC + EMAIL SUBSCRIPTION
# ════════════════════════════════════════════════════════════

resource "aws_sns_topic" "alerts" {
  name              = "${local.prefix}-alerts"
  kms_master_key_id = aws_kms_key.main.arn
  tags              = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ════════════════════════════════════════════════════════════
#  LAMBDA FUNCTION
# ════════════════════════════════════════════════════════════

resource "aws_lambda_function" "redactor" {
  function_name = "gg-encryptionservice"
  role          = aws_iam_role.lambda_role.arn
  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.lambda_repo.repository_url}:${var.image_tag}"
  publish       = true   # required for provisioned concurrency (creates a numeric version)

  memory_size                    = 5120   # 5 GB — needed for spaCy lg + names-dataset
  timeout                        = 600    # 10 min — covers cold start (30s) + large files
  reserved_concurrent_executions = var.max_concurrency  # prevents runaway parallelism

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      OUTPUT_BUCKET        = data.aws_s3_bucket.output.bucket
      TOKEN_MAP_BUCKET     = data.aws_s3_bucket.token_map.bucket
      MODE                 = var.mode
      CONFIDENCE_THRESHOLD = var.confidence
      MAX_FILE_MB          = var.max_file_mb
      DB_HOST              = var.db_host
      DB_PORT              = var.db_port
      DB_NAME              = var.db_name
      DB_USER              = var.db_user
      DB_PASSWORD          = var.db_password
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy_attachment.lambda_vpc,
  ]

  # The image_uri is owned by the deploy pipeline (deploy.sh runs
  # `aws lambda update-function-code` after each push). Ignoring it here
  # prevents Terraform from reverting to a stale tag on subsequent applies.
  lifecycle {
    ignore_changes = [image_uri]
  }

  tags = local.tags
}

# ── Provisioned concurrency — keeps N warm instances ready at all times ─────
# This eliminates the cold start problem (no more 30s init delay).
# Cost: ~$18/month extra per always-warm instance at 5 GB.
# Set to 0 to disable (cold starts will occur, init takes ~30s).
#
# NOTE: This pins provisioning to the version that Terraform last published.
# `deploy.sh` calls `aws lambda update-function-code` which creates new versions
# outside of Terraform; those new versions are NOT auto-warmed until the next
# `terraform apply` re-publishes. Re-run terraform apply after major releases
# if you need the newest code to be warm.
resource "aws_lambda_provisioned_concurrency_config" "redactor" {
  count                             = var.provisioned_concurrency > 0 ? 1 : 0
  function_name                     = aws_lambda_function.redactor.function_name
  qualifier                         = aws_lambda_function.redactor.version
  provisioned_concurrent_executions = var.provisioned_concurrency
}

# ════════════════════════════════════════════════════════════
#  CLOUDWATCH ALARM — Lambda errors
# ════════════════════════════════════════════════════════════

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.prefix}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Lambda errors in hotel PII redaction"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = { FunctionName = aws_lambda_function.redactor.function_name }

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "${local.prefix}-dlq-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Failed transcript in DLQ — needs manual review"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = { QueueName = aws_sqs_queue.dlq.name }

  tags = local.tags
}

# ════════════════════════════════════════════════════════════
#  S3 → LAMBDA TRIGGER
# ════════════════════════════════════════════════════════════

resource "aws_lambda_permission" "s3_invoke" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.redactor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = data.aws_s3_bucket.input.arn
}

resource "aws_s3_bucket_notification" "input_trigger" {
  bucket = data.aws_s3_bucket.input.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.redactor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".txt"
  }
  depends_on = [aws_lambda_permission.s3_invoke]
}

# ════════════════════════════════════════════════════════════
#  OUTPUTS
# ════════════════════════════════════════════════════════════

output "input_bucket"      { value = data.aws_s3_bucket.input.bucket }
output "output_bucket"     { value = data.aws_s3_bucket.output.bucket }
output "token_map_bucket"  { value = data.aws_s3_bucket.token_map.bucket }
output "ecr_repo_url"      { value = aws_ecr_repository.lambda_repo.repository_url }
output "lambda_function"   { value = aws_lambda_function.redactor.function_name }
output "dlq_url"           { value = aws_sqs_queue.dlq.url }
output "kms_key_arn"       { value = aws_kms_key.main.arn }

