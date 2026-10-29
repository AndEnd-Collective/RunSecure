# Alarm destinations are an optional pre-reviewed existing SNS topic. No topic
# subscription or test notification is created. Missing success/freshness metrics
# are expected while idle; heartbeat/coverage monitoring must be added by operators.
locals {
  telemetry_firehose_alarms = {
    processing = { metric = "ExecuteProcessing.Success", statistic = "Average", comparison = "LessThanThreshold", threshold = 1 }
    delivery   = { metric = "DeliveryToS3.Success", statistic = "Average", comparison = "LessThanThreshold", threshold = 1 }
    throttling = { metric = "ThrottledRecords", statistic = "Sum", comparison = "GreaterThanThreshold", threshold = 0 }
    freshness  = { metric = "DeliveryToS3.DataFreshness", statistic = "Maximum", comparison = "GreaterThanThreshold", threshold = 900 }
  }
  telemetry_subscription_alarm_sources = {
    for pair in setproduct(keys(local.telemetry_sources), ["DeliveryErrors", "DeliveryThrottling"]) : "${pair[0]}-${pair[1]}" => { kind = pair[0], metric = pair[1] }
  }
}
resource "aws_cloudwatch_metric_alarm" "telemetry_firehose" {
  for_each            = local.telemetry_firehose_alarms
  alarm_name          = "${var.name}-archive-${each.key}"
  alarm_description   = "Archive delivery or processing degraded; encrypted error objects may contain ORIGINAL SENSITIVE DATA. Investigate without copying payloads into tickets."
  namespace           = "AWS/Firehose"
  metric_name         = each.value.metric
  statistic           = each.value.statistic
  comparison_operator = each.value.comparison
  threshold           = each.value.threshold
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  dimensions          = { DeliveryStreamName = aws_kinesis_firehose_delivery_stream.telemetry_archive.name }
  alarm_actions       = local.telemetry_alarm_actions
  ok_actions          = local.telemetry_alarm_actions
}
resource "aws_cloudwatch_metric_alarm" "telemetry_lambda" {
  for_each            = toset(["Errors", "Throttles"])
  alarm_name          = "${var.name}-archive-normalizer-${lower(each.value)}"
  alarm_description   = "Normalizer invocation failed/throttled. Firehose retries are finite; check raw-sensitive error retention and source delivery."
  namespace           = "AWS/Lambda"
  metric_name         = each.value
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.telemetry_normalizer.function_name }
  alarm_actions       = local.telemetry_alarm_actions
}
resource "aws_cloudwatch_metric_alarm" "telemetry_processing_failures" {
  alarm_name          = "${var.name}-archive-rejected-records"
  alarm_description   = "Normalizer rejected/limited records; originals may exist ONLY in the encrypted POSSIBLY-SENSITIVE processing-error prefix."
  namespace           = "RunSecure/TelemetryArchive"
  metric_name         = "ProcessingFailures"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  dimensions          = { ArchiveName = var.name }
  alarm_actions       = local.telemetry_alarm_actions
}
resource "aws_cloudwatch_metric_alarm" "telemetry_subscription" {
  for_each            = local.telemetry_subscription_alarm_sources
  alarm_name          = "${var.name}-archive-${each.key}"
  alarm_description   = "CloudWatch subscription delivery failed/throttled; retries and retention are finite, so archive coverage may be incomplete."
  namespace           = "AWS/Logs"
  metric_name         = each.value.metric
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  dimensions          = { LogGroupName = local.telemetry_sources[each.value.kind], DestinationType = "Firehose", FilterName = aws_cloudwatch_log_subscription_filter.telemetry_archive[each.value.kind].name }
  alarm_actions       = local.telemetry_alarm_actions
}
resource "aws_cloudwatch_log_metric_filter" "telemetry_flow_skipdata" {
  name           = "${var.name}-flow-skipdata"
  log_group_name = aws_cloudwatch_log_group.telemetry_vpc_flow.name
  pattern        = "\"SKIPDATA\""
  metric_transformation {
    name      = "VpcFlowSkippedRecords"
    namespace = "RunSecure/TelemetryArchive"
    value     = "1"
    unit      = "Count"
  }
}
resource "aws_cloudwatch_metric_alarm" "telemetry_flow_skipdata" {
  alarm_name          = "${var.name}-archive-vpc-flow-skipped"
  alarm_description   = "VPC flow logs report SKIPDATA; archive is incomplete for this interval."
  namespace           = "RunSecure/TelemetryArchive"
  metric_name         = "VpcFlowSkippedRecords"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.telemetry_alarm_actions
}
