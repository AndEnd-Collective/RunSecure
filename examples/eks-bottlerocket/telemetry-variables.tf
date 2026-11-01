variable "telemetry_archive_retention_days" {
  description = "Finite archive/current+noncurrent retention. Processing errors may contain sensitive original records."
  type        = number
  default     = 90
  validation {
    condition     = var.telemetry_archive_retention_days >= 1 && var.telemetry_archive_retention_days <= 3650 && floor(var.telemetry_archive_retention_days) == var.telemetry_archive_retention_days
    error_message = "Choose an integer archive retention between 1 and 3650 days."
  }
}

variable "telemetry_alarm_topic_arn" {
  description = "Optional existing approved SNS alarm destination; no subscription or message is created by planning."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = var.telemetry_alarm_topic_arn == null || can(regex("^arn:aws:sns:${var.region}:${var.account_id}:[A-Za-z0-9_-]+$", var.telemetry_alarm_topic_arn))
    error_message = "Use an exact existing SNS topic in this account and region, or null."
  }
}

variable "telemetry_create_cloudtrail" {
  description = "Optional independent management-event trail to a separate archive prefix. Default off; never modifies an organization trail."
  type        = bool
  default     = false
}
