# AWS source contracts checked 2026-10-29:
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html
# https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html
# https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html
locals {
  telemetry_bucket_name = "${substr(var.name, 0, 20)}-${var.account_id}-${var.region}-telemetry"
  telemetry_bucket_arn  = "arn:aws:s3:::${local.telemetry_bucket_name}"
  telemetry_stream_arn  = "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/${var.name}-telemetry"
  telemetry_trail_arn   = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${var.name}-telemetry"
  telemetry_sources = {
    collector              = "/runsecure/${var.name}/telemetry"
    eks-control-plane      = aws_cloudwatch_log_group.cluster.name
    route53-dns            = aws_cloudwatch_log_group.dns.name
    network-firewall-flow  = aws_cloudwatch_log_group.firewall["FLOW"].name
    network-firewall-alert = aws_cloudwatch_log_group.firewall["ALERT"].name
    vpc-flow               = "/runsecure/${var.name}/vpc-flow"
  }
  telemetry_private_log_groups = [
    "/runsecure/${var.name}/telemetry", "/runsecure/${var.name}/vpc-flow",
    "/aws/lambda/${var.name}-telemetry-normalizer", "/runsecure/${var.name}/firehose-diagnostics",
    "/aws/eks/${var.name}/cluster", "/runsecure/${var.name}/dns",
    "/runsecure/${var.name}/firewall/flow", "/runsecure/${var.name}/firewall/alert"
  ]
  telemetry_object_arns   = ["${local.telemetry_bucket_arn}/archive/*", "${local.telemetry_bucket_arn}/processing-errors/*", "${local.telemetry_bucket_arn}/delivery-diagnostics/*"]
  telemetry_alarm_actions = var.telemetry_alarm_topic_arn == null ? [] : [var.telemetry_alarm_topic_arn]
}

resource "aws_kms_key" "telemetry_archive" {
  description             = "${var.name} telemetry archive and private diagnostic groups"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  lifecycle { prevent_destroy = true } # Keep ciphertext recoverable; removal needs reviewed source change.
  # In a key policy Resource '*' means THIS KEY, not every account key.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "AccountAdministrationAndIAMDelegation", Effect = "Allow",
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }, Resource = "*",
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:EnableKey", "kms:DisableKey", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:GetKeyRotationStatus", "kms:TagResource", "kms:UntagResource", "kms:ListResourceTags", "kms:UpdateKeyDescription", "kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
      },
      {
        Sid       = "ExactCloudWatchGroups", Effect = "Allow", Resource = "*",
        Principal = { Service = "logs.${var.region}.amazonaws.com" },
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"],
        Condition = { ArnEquals = { "kms:EncryptionContext:aws:logs:arn" = [for name in local.telemetry_private_log_groups : "arn:aws:logs:${var.region}:${var.account_id}:log-group:${name}"] } }
      }
      ], [for statement in [
        {
          Sid       = "ExactOptionalCloudTrail", Effect = "Allow", Resource = "*",
          Principal = { Service = "cloudtrail.amazonaws.com" },
          Action    = ["kms:GenerateDataKey"],
          Condition = { StringEquals = { "aws:SourceArn" = local.telemetry_trail_arn }, StringLike = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${var.account_id}:trail/${var.name}-telemetry" } }
        },
        {
          Sid       = "OptionalTrailDescribeKey", Effect = "Allow", Resource = "*",
          Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "kms:DescribeKey",
          Condition = { StringEquals = { "aws:SourceArn" = local.telemetry_trail_arn } }
        }
    ] : statement if var.telemetry_create_cloudtrail])
  })
}

resource "aws_s3_bucket" "telemetry_archive" {
  bucket        = local.telemetry_bucket_name
  force_destroy = false
}
resource "aws_s3_bucket_ownership_controls" "telemetry_archive" {
  bucket = aws_s3_bucket.telemetry_archive.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_public_access_block" "telemetry_archive" {
  bucket                  = aws_s3_bucket.telemetry_archive.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "telemetry_archive" {
  bucket = aws_s3_bucket.telemetry_archive.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "telemetry_archive" {
  bucket = aws_s3_bucket.telemetry_archive.id
  rule {
    bucket_key_enabled = false # Keep per-object KMS context, including error prefix.
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.telemetry_archive.arn
    }
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "telemetry_archive" {
  bucket = aws_s3_bucket.telemetry_archive.id
  rule {
    id     = "finite-retention"
    status = "Enabled"
    filter {}
    expiration { days = var.telemetry_archive_retention_days }
    noncurrent_version_expiration { noncurrent_days = var.telemetry_archive_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
  depends_on = [aws_s3_bucket_versioning.telemetry_archive]
}
resource "aws_s3_bucket_policy" "telemetry_archive" {
  bucket = aws_s3_bucket.telemetry_archive.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*",
        Action    = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketAcl", "s3:AbortMultipartUpload", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts"],
        Resource  = [local.telemetry_bucket_arn, "${local.telemetry_bucket_arn}/*"],
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyExplicitWrongEncryption", Effect = "Deny", Principal = "*", Action = "s3:PutObject", Resource = "${local.telemetry_bucket_arn}/*",
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" }, Null = { "s3:x-amz-server-side-encryption" = "false" } }
      },
      {
        Sid       = "DenyExplicitKMSWithoutExactKey", Effect = "Deny", Principal = "*", Action = "s3:PutObject", Resource = "${local.telemetry_bucket_arn}/*",
        Condition = { StringEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" }, Null = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = "true" } }
      },
      {
        Sid       = "DenyExplicitWrongKey", Effect = "Deny", Principal = "*", Action = "s3:PutObject", Resource = "${local.telemetry_bucket_arn}/*",
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.telemetry_archive.arn }, Null = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = "false" } }
      }
      ], [for statement in [
        {
          Sid       = "TrailBucketCheck", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:GetBucketAcl", Resource = local.telemetry_bucket_arn,
          Condition = { StringEquals = { "aws:SourceArn" = local.telemetry_trail_arn } }
        },
        {
          Sid       = "ExactTrailDelivery", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:PutObject", Resource = "${local.telemetry_bucket_arn}/cloudtrail/AWSLogs/${var.account_id}/*",
          Condition = { StringEquals = { "aws:SourceArn" = local.telemetry_trail_arn, "s3:x-amz-acl" = "bucket-owner-full-control" } }
        }
    ] : statement if var.telemetry_create_cloudtrail])
  })
}

resource "aws_cloudwatch_log_group" "telemetry" {
  name              = local.telemetry_sources.collector
  retention_in_days = 90
  kms_key_id        = aws_kms_key.telemetry_archive.arn
}
resource "aws_cloudwatch_log_group" "telemetry_vpc_flow" {
  name              = local.telemetry_sources.vpc-flow
  retention_in_days = 90
  kms_key_id        = aws_kms_key.telemetry_archive.arn
}
resource "aws_cloudwatch_log_group" "telemetry_lambda" {
  name              = "/aws/lambda/${var.name}-telemetry-normalizer"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.telemetry_archive.arn
}
resource "aws_cloudwatch_log_group" "telemetry_firehose" {
  name              = "/runsecure/${var.name}/firehose-diagnostics"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.telemetry_archive.arn
}
resource "aws_cloudwatch_log_stream" "telemetry_firehose" {
  name           = "delivery-errors"
  log_group_name = aws_cloudwatch_log_group.telemetry_firehose.name
}

resource "aws_iam_role" "telemetry_collector" {
  name = "${var.name}-telemetry-gateway"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect    = "Allow", Principal = { Service = "pods.eks.amazonaws.com" }, Action = ["sts:AssumeRole", "sts:TagSession"],
      Condition = { StringEquals = { "aws:RequestTag/eks-cluster-arn" = local.cluster_arn, "aws:RequestTag/eks-cluster-name" = var.name, "aws:RequestTag/kubernetes-namespace" = "runsecure-observability", "aws:RequestTag/kubernetes-service-account" = "runsecure-telemetry-gateway" } }
    }]
  })
}
resource "aws_iam_role_policy" "telemetry_collector" {
  role = aws_iam_role.telemetry_collector.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.telemetry.arn}:log-stream:*"
  }] })
}
resource "aws_eks_pod_identity_association" "telemetry_collector" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "runsecure-observability"
  service_account = "runsecure-telemetry-gateway"
  role_arn        = aws_iam_role.telemetry_collector.arn
}

resource "aws_iam_role" "telemetry_flow" {
  name = "${var.name}-vpc-flow"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = { StringEquals = { "aws:SourceAccount" = var.account_id }, ArnLike = { "aws:SourceArn" = "arn:aws:ec2:${var.region}:${var.account_id}:vpc-flow-log/*" } }
  }] })
}
resource "aws_iam_role_policy" "telemetry_flow" {
  role = aws_iam_role.telemetry_flow.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"], Resource = "${aws_cloudwatch_log_group.telemetry_vpc_flow.arn}:*" },
    # DescribeLogGroups has no resource-level authorization; region-bound discovery.
    { Effect = "Allow", Action = "logs:DescribeLogGroups", Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } }
  ] })
}
resource "aws_flow_log" "telemetry" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  iam_role_arn             = aws_iam_role.telemetry_flow.arn
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.telemetry_vpc_flow.arn
  max_aggregation_interval = 60
  depends_on               = [aws_iam_role_policy.telemetry_flow]
}

resource "aws_iam_role" "telemetry_lambda" {
  name               = "${var.name}-telemetry-normalizer"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy" "telemetry_lambda" {
  role   = aws_iam_role.telemetry_lambda.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.telemetry_lambda.arn}:log-stream:*" }] })
}
data "archive_file" "telemetry_normalizer" {
  type        = "zip"
  output_path = "${path.module}/.terraform/telemetry-normalizer.zip"
  source {
    content  = file("${path.module}/archive/normalizer.py")
    filename = "normalizer.py"
  }
}
resource "aws_lambda_function" "telemetry_normalizer" {
  function_name                  = "${var.name}-telemetry-normalizer"
  role                           = aws_iam_role.telemetry_lambda.arn
  filename                       = data.archive_file.telemetry_normalizer.output_path
  source_code_hash               = data.archive_file.telemetry_normalizer.output_base64sha256
  handler                        = "normalizer.handler"
  runtime                        = "python3.13"
  architectures                  = ["arm64"]
  timeout                        = 60
  memory_size                    = 256
  reserved_concurrent_executions = 2
  publish                        = true
  environment {
    variables = {
      EXPECTED_ACCOUNT_ID = var.account_id
      ARCHIVE_NAME        = var.name
      SOURCE_GROUPS_JSON  = jsonencode({ for kind, group in local.telemetry_sources : group => kind })
    }
  }
  logging_config {
    log_format = "Text" # Embedded Metric Format JSON is emitted directly.
    log_group  = aws_cloudwatch_log_group.telemetry_lambda.name
  }
  depends_on = [aws_iam_role_policy.telemetry_lambda]
}

resource "aws_iam_role" "telemetry_firehose" {
  name = "${var.name}-telemetry-firehose"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Principal = { Service = "firehose.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = { StringEquals = { "sts:ExternalId" = var.account_id } }
  }] })
}
resource "aws_iam_role_policy" "telemetry_firehose" {
  role = aws_iam_role.telemetry_firehose.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:AbortMultipartUpload", "s3:GetObject", "s3:PutObject", "s3:ListMultipartUploadParts"], Resource = local.telemetry_object_arns },
    { Effect = "Allow", Action = ["s3:GetBucketLocation", "s3:ListBucketMultipartUploads"], Resource = local.telemetry_bucket_arn },
    { Effect = "Allow", Action = "s3:ListBucket", Resource = local.telemetry_bucket_arn, Condition = { StringLike = { "s3:prefix" = ["archive/*", "processing-errors/*", "delivery-diagnostics/*"] } } },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.telemetry_archive.arn,
    Condition = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com", "kms:CallerAccount" = var.account_id }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = local.telemetry_object_arns } } },
    { Effect = "Allow", Action = ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"], Resource = aws_lambda_function.telemetry_normalizer.qualified_arn },
    { Effect = "Allow", Action = "logs:PutLogEvents", Resource = aws_cloudwatch_log_stream.telemetry_firehose.arn }
  ] })
}
resource "aws_kinesis_firehose_delivery_stream" "telemetry_archive" {
  name        = "${var.name}-telemetry"
  destination = "extended_s3"
  server_side_encryption { enabled = true }
  extended_s3_configuration {
    role_arn            = aws_iam_role.telemetry_firehose.arn
    bucket_arn          = aws_s3_bucket.telemetry_archive.arn
    kms_key_arn         = aws_kms_key.telemetry_archive.arn
    prefix              = "archive/!{timestamp:yyyy/MM/dd/HH}/"
    error_output_prefix = "processing-errors/POSSIBLY-SENSITIVE/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH}/"
    compression_format  = "GZIP"
    s3_backup_mode      = "Disabled" # Never back up all unredacted source records to the normal archive.
    buffering_size      = 5
    buffering_interval  = 60
    processing_configuration {
      enabled = true
      processors {
        type = "Lambda"
        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.telemetry_normalizer.qualified_arn
        }
        parameters {
          parameter_name  = "BufferSizeInMBs"
          parameter_value = "1"
        }
        parameters {
          parameter_name  = "BufferIntervalInSeconds"
          parameter_value = "60"
        }
        parameters {
          parameter_name  = "NumberOfRetries"
          parameter_value = "3"
        }
      }
    }
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.telemetry_firehose.name
      log_stream_name = aws_cloudwatch_log_stream.telemetry_firehose.name
    }
  }
  depends_on = [aws_iam_role_policy.telemetry_firehose, aws_s3_bucket_policy.telemetry_archive, aws_s3_bucket_server_side_encryption_configuration.telemetry_archive, aws_s3_bucket_public_access_block.telemetry_archive]
}
resource "aws_iam_role" "telemetry_subscription" {
  name = "${var.name}-logs-to-firehose"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Principal = { Service = "logs.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = { StringEquals = { "aws:SourceAccount" = var.account_id }, ArnLike = { "aws:SourceArn" = [for name in concat(values(local.telemetry_sources), values(local.telemetry_diagnostic_groups)) : "arn:aws:logs:${var.region}:${var.account_id}:log-group:${name}:*"] } }
  }] })
}
resource "aws_iam_role_policy" "telemetry_subscription" {
  role   = aws_iam_role.telemetry_subscription.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["firehose:PutRecord", "firehose:PutRecordBatch"], Resource = [local.telemetry_stream_arn, local.telemetry_diagnostic_stream_arn] }] })
}
resource "aws_cloudwatch_log_subscription_filter" "telemetry_archive" {
  for_each        = local.telemetry_sources
  name            = "${var.name}-archive-${each.key}"
  log_group_name  = each.value
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.telemetry_archive.arn
  role_arn        = aws_iam_role.telemetry_subscription.arn
  depends_on      = [aws_iam_role_policy.telemetry_subscription, aws_cloudwatch_log_group.telemetry, aws_cloudwatch_log_group.telemetry_vpc_flow]
}

resource "aws_cloudtrail" "telemetry" {
  count                         = var.telemetry_create_cloudtrail ? 1 : 0
  name                          = "${var.name}-telemetry"
  s3_bucket_name                = aws_s3_bucket.telemetry_archive.id
  s3_key_prefix                 = "cloudtrail"
  kms_key_id                    = aws_kms_key.telemetry_archive.arn
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.telemetry_archive]
}

output "collector_role_arn" { value = aws_iam_role.telemetry_collector.arn }
output "telemetry_log_group_name" { value = aws_cloudwatch_log_group.telemetry.name }
output "telemetry_log_group_arn" { value = aws_cloudwatch_log_group.telemetry.arn }
output "telemetry_logs_endpoint_id" { value = aws_vpc_endpoint.platform["logs"].id }
output "telemetry_archive" {
  value = { bucket_name = aws_s3_bucket.telemetry_archive.id, key_arn = aws_kms_key.telemetry_archive.arn, firehose_arn = aws_kinesis_firehose_delivery_stream.telemetry_archive.arn, error_prefix = "processing-errors/POSSIBLY-SENSITIVE/", retention_days = var.telemetry_archive_retention_days, cloudtrail_enabled = var.telemetry_create_cloudtrail }
}
