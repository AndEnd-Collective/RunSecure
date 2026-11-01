# Archive delivery-system diagnostics separately, WITHOUT the Lambda transformer
# and WITHOUT this stream generating logs consumed by itself. These are raw AWS
# CloudWatch subscription envelopes (gzip/base64 payloads), not Cornerstone claims.
# Restricted prefix may contain unredacted service diagnostics; alarm on failure.
locals {
  telemetry_diagnostic_stream_arn = "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/${var.name}-telemetry-diagnostics"
  telemetry_diagnostic_groups = {
    lambda   = aws_cloudwatch_log_group.telemetry_lambda.name
    firehose = aws_cloudwatch_log_group.telemetry_firehose.name
  }
}

resource "aws_kinesis_firehose_delivery_stream" "telemetry_diagnostics" {
  name        = "${var.name}-telemetry-diagnostics"
  destination = "extended_s3"
  server_side_encryption { enabled = true }
  extended_s3_configuration {
    role_arn            = aws_iam_role.telemetry_firehose.arn
    bucket_arn          = aws_s3_bucket.telemetry_archive.arn
    kms_key_arn         = aws_kms_key.telemetry_archive.arn
    prefix              = "delivery-diagnostics/POSSIBLY-SENSITIVE/!{timestamp:yyyy/MM/dd/HH}/"
    error_output_prefix = "delivery-diagnostics/POSSIBLY-SENSITIVE/errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH}/"
    compression_format  = "GZIP"
    s3_backup_mode      = "Disabled"
    buffering_size      = 5
    buffering_interval  = 60
    cloudwatch_logging_options { enabled = false }
  }
  depends_on = [aws_iam_role_policy.telemetry_firehose, aws_s3_bucket_policy.telemetry_archive, aws_s3_bucket_server_side_encryption_configuration.telemetry_archive, aws_s3_bucket_public_access_block.telemetry_archive]
}

resource "aws_cloudwatch_log_subscription_filter" "telemetry_diagnostics" {
  for_each        = local.telemetry_diagnostic_groups
  name            = "${var.name}-archive-${each.key}-diagnostics"
  log_group_name  = each.value
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.telemetry_diagnostics.arn
  role_arn        = aws_iam_role.telemetry_subscription.arn
  depends_on      = [aws_iam_role_policy.telemetry_subscription]
}

resource "aws_cloudwatch_metric_alarm" "telemetry_diagnostic_delivery" {
  alarm_name          = "${var.name}-telemetry-diagnostic-delivery-failed"
  namespace           = "AWS/Firehose"
  metric_name         = "DeliveryToS3.Success"
  dimensions          = { DeliveryStreamName = aws_kinesis_firehose_delivery_stream.telemetry_diagnostics.name }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.telemetry_alarm_actions
  alarm_description   = "Diagnostic archive delivery failed; inspect Firehose service metrics. No self-subscribed diagnostic logs exist. Idle streams need an independent heartbeat."
}

# Source-side failures can prevent every record from reaching Firehose, leaving
# its delivery metric absent. Monitor both subscriptions without adding a log
# sink to the diagnostic stream itself (which would create a feedback loop).
resource "aws_cloudwatch_metric_alarm" "telemetry_diagnostic_subscription" {
  for_each = {
    for pair in setproduct(keys(local.telemetry_diagnostic_groups), ["DeliveryErrors", "DeliveryThrottling"]) : "${pair[0]}-${pair[1]}" => { kind = pair[0], metric = pair[1] }
  }
  alarm_name          = "${var.name}-telemetry-diagnostic-${each.key}"
  alarm_description   = "Diagnostic CloudWatch subscription delivery failed/throttled; service retry and source retention windows are finite."
  namespace           = "AWS/Logs"
  metric_name         = each.value.metric
  dimensions          = { LogGroupName = local.telemetry_diagnostic_groups[each.value.kind], DestinationType = "Firehose", FilterName = aws_cloudwatch_log_subscription_filter.telemetry_diagnostics[each.value.kind].name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.telemetry_alarm_actions
}
