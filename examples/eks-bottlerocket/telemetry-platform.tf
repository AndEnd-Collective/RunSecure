# Exact private endpoint peers for the telemetry chart. Known AZ count keeps
# the data-source instance keys stable while endpoint ENIs resolve at apply.
data "aws_network_interface" "telemetry_logs" {
  count = length(var.zones)
  id    = sort(tolist(aws_vpc_endpoint.platform["logs"].network_interface_ids))[count.index]
}

output "telemetry_logs_endpoint_cidrs" {
  description = "Exact private CloudWatch Logs endpoint /32 peers; no public AWS exception."
  value       = [for eni in data.aws_network_interface.telemetry_logs : "${eni.private_ip}/32"]
}

output "telemetry_context" {
  description = "Non-secret deployment context for controller and collector values."
  value = {
    cluster_name = var.name
    account_id   = var.account_id
    region       = var.region
    environment  = "Testing"
  }
}
