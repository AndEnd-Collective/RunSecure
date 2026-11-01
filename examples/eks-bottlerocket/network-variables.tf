variable "vpc_cidr" {
  description = "Dedicated IPv4 VPC. No IPv6 addresses or egress-only gateway are configured."
  type        = string
  default     = "10.80.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be an IPv4 CIDR."
  }
}

variable "zones" {
  description = "Same-AZ inspection lanes. VPC preconditions reject overlapping subnet CIDRs or any subnet outside vpc_cidr."
  type = map(object({
    management_cidr = string
    execution_cidr  = string
    firewall_cidr   = string
    public_cidr     = string
  }))
  default = {
    us-east-2a = { management_cidr = "10.80.0.0/24", execution_cidr = "10.80.16.0/20", firewall_cidr = "10.80.240.0/28", public_cidr = "10.80.242.0/24" }
    us-east-2b = { management_cidr = "10.80.1.0/24", execution_cidr = "10.80.32.0/20", firewall_cidr = "10.80.240.16/28", public_cidr = "10.80.243.0/24" }
  }
  validation {
    condition = length(var.zones) >= 2 && alltrue(flatten([
      for zone, lane in var.zones : [
        startswith(zone, var.region),
        can(cidrnetmask(lane.management_cidr)), can(cidrnetmask(lane.execution_cidr)),
        can(cidrnetmask(lane.firewall_cidr)), can(cidrnetmask(lane.public_cidr))
      ]
    ]))
    error_message = "Use at least two AZs in region, with valid IPv4 subnet CIDRs."
  }
}

variable "github_execution_domains" {
  description = "Reviewed finite GitHub execution hostnames, including exact current Actions service names. No suffixes or wildcards. An empty set quarantines execution internet traffic. See GitHub's self-hosted runner communication requirements and review redirects individually."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for domain in var.github_execution_domains :
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", domain)) &&
      anytrue([for suffix in ["github.com", "githubusercontent.com", "githubassets.com", "actions.githubusercontent.com", "blob.core.windows.net"] : domain == suffix || endswith(domain, ".${suffix}")])
    ])
    error_message = "Use exact lowercase hostnames from the reviewed GitHub runner communication inventory; no wildcard, whitespace, port, URL or arbitrary domain."
  }
}

variable "additional_platform_dns_domains" {
  description = "Additional exact DNS names needed by reviewed private endpoint/CNAME chains and cluster bootstrap. DNS-only exceptions: these never add internet firewall pass rules. No wildcard AWS suffixes."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for domain in var.additional_platform_dns_domains :
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", domain))
    ])
    error_message = "DNS exceptions must be exact lowercase DNS names without wildcards, whitespace, ports or newlines."
  }
}
