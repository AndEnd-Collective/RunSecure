# Uses the existing fixture variable shape; no AWS calls or apply.
mock_provider "aws" {
  override_during = plan
  mock_data "aws_network_interface" { defaults = { private_ip = "10.80.0.8" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "123456789012" } }
  mock_resource "aws_eks_cluster" { defaults = { endpoint = "https://fixture.cluster.eks.amazonaws.com" } }
  mock_resource "aws_vpc_endpoint" { defaults = { dns_entry = [{ dns_name = "fixture.vpce.amazonaws.com", hosted_zone_id = "ZFIXTURE" }], network_interface_ids = ["eni-aaaaaaaa", "eni-bbbbbbbb"] } }
  mock_resource "aws_networkfirewall_firewall" {
    defaults = { arn = "arn:aws:network-firewall:us-east-2:123456789012:firewall/fixture", firewall_status = [{ sync_states = [
      { availability_zone = "us-east-2a", attachment = [{ endpoint_id = "vpce-aaaaaaaa", subnet_id = "subnet-aaaaaaaa", status = "READY" }] },
      { availability_zone = "us-east-2b", attachment = [{ endpoint_id = "vpce-bbbbbbbb", subnet_id = "subnet-bbbbbbbb", status = "READY" }] }
    ] }] }
  }
  mock_resource "aws_networkfirewall_rule_group" { defaults = { arn = "arn:aws:network-firewall:us-east-2:123456789012:stateful-rulegroup/fixture" } }
  mock_resource "aws_cloudwatch_log_stream" { defaults = { arn = "arn:aws:logs:us-east-2:123456789012:log-group:/fixture:log-stream:delivery-errors" } }
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:us-east-2:123456789012:log-group:/fixture" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::123456789012:role/fixture" } }
  mock_resource "aws_s3_bucket" { defaults = { arn = "arn:aws:s3:::fixture-archive" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:us-east-2:123456789012:key/11111111-1111-1111-1111-111111111111" } }
  mock_resource "aws_lambda_function" { defaults = { arn = "arn:aws:lambda:us-east-2:123456789012:function:fixture", qualified_arn = "arn:aws:lambda:us-east-2:123456789012:function:fixture:1" } }
  mock_resource "aws_kinesis_firehose_delivery_stream" { defaults = { arn = "arn:aws:firehose:us-east-2:123456789012:deliverystream/fixture" } }
}
variables {
  account_id                   = "123456789012"
  cluster_role_arn             = "arn:aws:iam::123456789012:role/fixture-eks"
  cni_role_arn                 = "arn:aws:iam::123456789012:role/fixture-cni"
  operator_role_arn            = "arn:aws:iam::123456789012:role/fixture-operator"
  operator_cidrs               = ["10.200.0.0/24"]
  kubernetes_version           = "1.36"
  bottlerocket_release_version = "1.65.0-abcdef01"
  pull_repository_arns         = ["arn:aws:ecr:us-east-2:123456789012:repository/runsecure/node"]
  addon_versions               = { vpc_cni = "v1.21.0-eksbuild.1", pod_identity_agent = "v1.3.0-eksbuild.1", kube_proxy = "v1.36.0-eksbuild.1", coredns = "v1.12.0-eksbuild.1" }
}
run "archive_security_boundaries" {
  command = plan
  assert {
    condition     = !aws_s3_bucket.telemetry_archive.force_destroy && aws_s3_bucket_versioning.telemetry_archive.versioning_configuration[0].status == "Enabled" && aws_s3_bucket_public_access_block.telemetry_archive.block_public_policy && aws_s3_bucket_public_access_block.telemetry_archive.restrict_public_buckets
    error_message = "Archive must preserve data and block public access."
  }
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.telemetry_archive.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms" && !one(aws_s3_bucket_server_side_encryption_configuration.telemetry_archive.rule).bucket_key_enabled
    error_message = "Use object-context KMS encryption, without bucket-key context widening."
  }
  assert {
    condition     = aws_eks_pod_identity_association.telemetry_collector.namespace == "runsecure-observability" && aws_eks_pod_identity_association.telemetry_collector.service_account == "runsecure-telemetry-gateway" && alltrue([for statement in jsondecode(aws_iam_role_policy.telemetry_collector.policy).Statement : statement.Action == ["logs:CreateLogStream", "logs:PutLogEvents"]])
    error_message = "Only dedicated gateway gets stream-write permission; no bucket or KMS identity."
  }
  assert {
    condition     = toset(keys(local.telemetry_sources)) == toset(["collector", "eks-control-plane", "route53-dns", "network-firewall-flow", "network-firewall-alert", "vpc-flow"]) && length(aws_cloudwatch_log_subscription_filter.telemetry_archive) == 6
    error_message = "Archive only explicit source groups; no diagnostic self-recursion."
  }
  assert {
    condition     = aws_kinesis_firehose_delivery_stream.telemetry_archive.extended_s3_configuration[0].error_output_prefix == "processing-errors/POSSIBLY-SENSITIVE/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH}/" && aws_kinesis_firehose_delivery_stream.telemetry_archive.extended_s3_configuration[0].s3_backup_mode == "Disabled" && aws_lambda_function.telemetry_normalizer.runtime == "python3.13" && aws_lambda_function.telemetry_normalizer.architectures == tolist(["arm64"])
    error_message = "Failures need a clearly sensitive encrypted error channel and supported normalizer runtime."
  }
  assert {
    condition     = alltrue(flatten([for policy in [aws_iam_role_policy.telemetry_collector.policy, aws_iam_role_policy.telemetry_firehose.policy, aws_iam_role_policy.telemetry_lambda.policy, aws_iam_role_policy.telemetry_subscription.policy] : [for statement in jsondecode(policy).Statement : [for action in try(tolist(statement.Action), [statement.Action]) : !strcontains(action, "*")]]]))
    error_message = "Every service permission must name actions explicitly."
  }
}
run "reject_unbounded_retention" {
  command = plan
  variables { telemetry_archive_retention_days = 0 }
  expect_failures = [var.telemetry_archive_retention_days]
}
run "optional_trail_is_separate_and_validated" {
  command = plan
  variables { telemetry_create_cloudtrail = true }
  assert {
    condition     = length(aws_cloudtrail.telemetry) == 1 && aws_cloudtrail.telemetry[0].enable_log_file_validation && aws_cloudtrail.telemetry[0].s3_key_prefix == "cloudtrail" && aws_cloudtrail.telemetry[0].is_multi_region_trail
    error_message = "Optional trail must preserve native validation in a separate prefix."
  }
  assert {
    condition     = [for s in jsondecode(aws_kms_key.telemetry_archive.policy).Statement : s.Condition.StringEquals["aws:SourceArn"] if s.Sid == "ExactOptionalCloudTrail"] == ["arn:aws:cloudtrail:us-east-2:123456789012:trail/runsecure-example-telemetry"]
    error_message = "Optional CloudTrail key use is bound to this exact trail."
  }
}

run "diagnostics_are_archived_without_recursion" {
  command = plan
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.telemetry_diagnostic_subscription) == 4
    error_message = "Every diagnostic source needs delivery-error and throttling alarms, even when no records reach the destination."
  }
  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.telemetry_diagnostics) == 2 && !aws_kinesis_firehose_delivery_stream.telemetry_diagnostics.extended_s3_configuration[0].cloudwatch_logging_options[0].enabled && length(aws_kinesis_firehose_delivery_stream.telemetry_diagnostics.extended_s3_configuration[0].processing_configuration) == 0
    error_message = "Delivery diagnostics must reach their separate raw-sensitive archive without invoking the normalizer or logging back into themselves."
  }
  assert {
    condition     = aws_kinesis_firehose_delivery_stream.telemetry_diagnostics.extended_s3_configuration[0].prefix == "delivery-diagnostics/POSSIBLY-SENSITIVE/!{timestamp:yyyy/MM/dd/HH}/" && length(output.telemetry_logs_endpoint_cidrs) == length(var.zones)
    error_message = "Keep diagnostic data segregated and expose exact endpoint peers."
  }
}
