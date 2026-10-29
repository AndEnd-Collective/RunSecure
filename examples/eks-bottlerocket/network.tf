# Native support was released in hashicorp/aws 6.71.0 on 2026-10-28:
# https://github.com/hashicorp/terraform-provider-aws/releases/tag/v6.71.0
# Each pass rule combines DNS-derived destination identity AND exact visible SNI:
# https://docs.aws.amazon.com/network-firewall/latest/developerguide/route53-resolved-ip-validation-rules.html
locals {
  all_subnet_cidrs = flatten([for lane in values(var.zones) : values(lane)])
  subnet_ranges = [for cidr in local.all_subnet_cidrs : {
    first = sum([for index, octet in split(".", cidrhost(cidr, 0)) : tonumber(octet) * pow(256, 3 - index)])
    last  = sum([for index, octet in split(".", cidrhost(cidr, -1)) : tonumber(octet) * pow(256, 3 - index)])
  }]
  vpc_first     = sum([for index, octet in split(".", cidrhost(var.vpc_cidr, 0)) : tonumber(octet) * pow(256, 3 - index)])
  vpc_last      = sum([for index, octet in split(".", cidrhost(var.vpc_cidr, -1)) : tonumber(octet) * pow(256, 3 - index)])
  service_first = sum([for index, octet in split(".", cidrhost(local.service_cidr, 0)) : tonumber(octet) * pow(256, 3 - index)])
  service_last  = sum([for index, octet in split(".", cidrhost(local.service_cidr, -1)) : tonumber(octet) * pow(256, 3 - index)])
  private_cidr_ranges = [for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] : {
    first = sum([for index, octet in split(".", cidrhost(cidr, 0)) : tonumber(octet) * pow(256, 3 - index)])
    last  = sum([for index, octet in split(".", cidrhost(cidr, -1)) : tonumber(octet) * pow(256, 3 - index)])
  }]
  management_cidrs      = [for lane in values(var.zones) : lane.management_cidr]
  execution_cidrs       = [for lane in values(var.zones) : lane.execution_cidr]
  private_cidrs         = concat(local.management_cidrs, local.execution_cidrs)
  management_subnet_ids = [for subnet in values(aws_subnet.management) : subnet.id]
  execution_subnet_ids  = [for subnet in values(aws_subnet.execution) : subnet.id]
  firewall_endpoint_ids = {
    for state in aws_networkfirewall_firewall.this.firewall_status[0].sync_states :
    state.availability_zone => state.attachment[0].endpoint_id
  }
  # PrivateLink names and the generated Kubernetes API hostname are exact.
  # CNAME chains remain inspected: an unreviewed target fails DNS resolution.
  platform_dns_domains = toset(concat([
    for service in ["ec2", "eks", "eks-auth", "sts", "logs", "secretsmanager", "s3"] : "${service}.${var.region}.amazonaws.com"
    ], [
    "api.ecr.${var.region}.amazonaws.com",
    "prod-${var.region}-starport-layer-bucket.s3.${var.region}.amazonaws.com",
    trimsuffix(trimprefix(aws_eks_cluster.this.endpoint, "https://"), "/")
    ], [
    for repository in var.pull_repository_arns : "${split(":", repository)[4]}.dkr.ecr.${split(":", repository)[3]}.amazonaws.com"
    ], flatten([
      for endpoint in values(aws_vpc_endpoint.platform) : [for entry in endpoint.dns_entry : entry.dns_name if !strcontains(entry.dns_name, "*")]
  ]), tolist(var.additional_platform_dns_domains)))
  github_rules = concat([
    "pass tls [${join(",", local.management_cidrs)}] any -> $EXTERNAL_NET 443 (msg:\"Management GitHub API\"; flow:to_server,established; tls.sni; content:\"api.github.com\"; nocase; startswith; endswith; aws_route_53_resolved_domain:\"api.github.com\"; alert; sid:1001;)"
    ], [for index, domain in sort(tolist(var.github_execution_domains)) :
    "pass tls [${join(",", local.execution_cidrs)}] any -> $EXTERNAL_NET 443 (msg:\"Execution GitHub ${domain}\"; flow:to_server,established; tls.sni; content:\"${domain}\"; nocase; startswith; endswith; aws_route_53_resolved_domain:\"${domain}\"; alert; sid:${2000 + index};)"
  ])
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
  lifecycle {
    precondition {
      condition     = anytrue([for private in local.private_cidr_ranges : local.vpc_first >= private.first && local.vpc_last <= private.last])
      error_message = "The entire VPC must lie inside RFC1918 space; Pod private-destination protections depend on this."
    }
    precondition {
      condition     = local.vpc_last < local.service_first || local.service_last < local.vpc_first
      error_message = "The VPC must not overlap the fixed Kubernetes service CIDR."
    }
    precondition {
      condition     = alltrue([for subnet in local.subnet_ranges : subnet.first >= local.vpc_first && subnet.last <= local.vpc_last])
      error_message = "Every subnet CIDR must be entirely inside vpc_cidr."
    }
    precondition {
      condition = alltrue(flatten([for i, left in local.subnet_ranges : [
        for j, right in local.subnet_ranges : i == j || left.last < right.first || right.last < left.first
      ]]))
      error_message = "All subnet CIDRs must be nonoverlapping, including management, execution, firewall and NAT lanes."
    }
  }
}

resource "aws_subnet" "management" {
  for_each                = var.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value.management_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-management-${each.key}" }
}

resource "aws_subnet" "execution" {
  for_each                = var.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value.execution_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-execution-${each.key}" }
}

resource "aws_subnet" "firewall" {
  for_each                = var.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value.firewall_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-firewall-${each.key}" }
}

resource "aws_subnet" "public" {
  for_each                = var.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value.public_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-nat-${each.key}" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_eip" "nat" {
  for_each = var.zones
  domain   = "vpc"
  tags     = { Name = "${var.name}-nat-${each.key}" }
}

resource "aws_nat_gateway" "this" {
  for_each      = var.zones
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id
  depends_on    = [aws_internet_gateway.this]
  tags          = { Name = "${var.name}-${each.key}" }
}

resource "aws_route_table" "management" {
  for_each = var.zones
  vpc_id   = aws_vpc.this.id
  route {
    cidr_block      = "0.0.0.0/0"
    vpc_endpoint_id = local.firewall_endpoint_ids[each.key]
  }
  tags = { Name = "${var.name}-management-${each.key}" }
}

resource "aws_route_table" "execution" {
  for_each = var.zones
  vpc_id   = aws_vpc.this.id
  route {
    cidr_block      = "0.0.0.0/0"
    vpc_endpoint_id = local.firewall_endpoint_ids[each.key]
  }
  tags = { Name = "${var.name}-execution-${each.key}" }
}

resource "aws_route_table" "firewall" {
  for_each = var.zones
  vpc_id   = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[each.key].id
  }
  tags = { Name = "${var.name}-firewall-${each.key}" }
}

# NAT return traffic must traverse the SAME firewall endpoint as outbound traffic.
# No conditional fallback route or alternate NAT target is present.
resource "aws_route_table" "public" {
  for_each = var.zones
  vpc_id   = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  dynamic "route" {
    for_each = toset([each.value.management_cidr, each.value.execution_cidr])
    content {
      cidr_block      = route.value
      vpc_endpoint_id = local.firewall_endpoint_ids[each.key]
    }
  }
  tags = { Name = "${var.name}-nat-${each.key}" }
}

resource "aws_route_table_association" "management" {
  for_each       = var.zones
  subnet_id      = aws_subnet.management[each.key].id
  route_table_id = aws_route_table.management[each.key].id
}
resource "aws_route_table_association" "execution" {
  for_each       = var.zones
  subnet_id      = aws_subnet.execution[each.key].id
  route_table_id = aws_route_table.execution[each.key].id
}
resource "aws_route_table_association" "firewall" {
  for_each       = var.zones
  subnet_id      = aws_subnet.firewall[each.key].id
  route_table_id = aws_route_table.firewall[each.key].id
}
resource "aws_route_table_association" "public" {
  for_each       = var.zones
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public[each.key].id
}

resource "aws_route53_resolver_firewall_config" "this" {
  resource_id        = aws_vpc.this.id
  firewall_fail_open = "DISABLED"
}
resource "aws_route53_resolver_firewall_rule_group" "this" {
  name = "${var.name}-dns"
}
resource "aws_route53_resolver_firewall_domain_list" "allowed" {
  name    = "${var.name}-dns-allowed"
  domains = sort(tolist(setunion(local.platform_dns_domains, var.github_execution_domains, toset(["api.github.com"]))))
}
resource "aws_route53_resolver_firewall_domain_list" "blocked" {
  name    = "${var.name}-dns-blocked"
  domains = ["*"] # A deny catch-all, never a wildcard allow exception.
}
resource "aws_route53_resolver_firewall_rule" "allowed" {
  name                               = "${var.name}-dns-allowed"
  action                             = "ALLOW"
  firewall_domain_list_id            = aws_route53_resolver_firewall_domain_list.allowed.id
  firewall_rule_group_id             = aws_route53_resolver_firewall_rule_group.this.id
  firewall_domain_redirection_action = "INSPECT_REDIRECTION_DOMAIN"
  priority                           = 100
}
resource "aws_route53_resolver_firewall_rule" "blocked" {
  name                    = "${var.name}-dns-blocked"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.blocked.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.this.id
  priority                = 200
}
resource "aws_route53_resolver_firewall_rule_group_association" "this" {
  name                   = "${var.name}-dns"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.this.id
  vpc_id                 = aws_vpc.this.id
  priority               = 100
  mutation_protection    = "ENABLED"
  depends_on             = [aws_route53_resolver_firewall_rule.allowed, aws_route53_resolver_firewall_rule.blocked, aws_route53_resolver_firewall_config.this]
}

# Stateless forwarding is NOT a pass: only TCP/443 and its return path reach
# stateful inspection. UDP (including QUIC/DNS), ICMP, other TCP and fragments drop.
resource "aws_networkfirewall_rule_group" "transport" {
  name     = "${var.name}-transport"
  type     = "STATELESS"
  capacity = 100
  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 10
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              protocols = [6]
              dynamic "source" {
                for_each = local.private_cidrs
                content { address_definition = source.value }
              }
              destination { address_definition = "0.0.0.0/0" }
              destination_port {
                from_port = 443
                to_port   = 443
              }
            }
          }
        }
        stateless_rule {
          priority = 20
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              protocols = [6]
              source { address_definition = "0.0.0.0/0" }
              source_port {
                from_port = 443
                to_port   = 443
              }
              dynamic "destination" {
                for_each = local.private_cidrs
                content { address_definition = destination.value }
              }
            }
          }
        }
      }
    }
  }
}

resource "aws_networkfirewall_rule_group" "github" {
  name     = "${var.name}-github"
  type     = "STATEFUL"
  capacity = 100
  rule_group {
    stateful_rule_options { rule_order = "STRICT_ORDER" }
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set { definition = local.private_cidrs }
      }
    }
    rules_source { rules_string = join("\n", local.github_rules) }
  }
}

resource "aws_networkfirewall_firewall_policy" "this" {
  name = var.name
  firewall_policy {
    stateless_default_actions          = ["aws:drop"]
    stateless_fragment_default_actions = ["aws:drop"]
    stateless_rule_group_reference {
      priority     = 100
      resource_arn = aws_networkfirewall_rule_group.transport.arn
    }
    stateful_engine_options {
      rule_order              = "STRICT_ORDER"
      stream_exception_policy = "DROP"
    }
    stateful_default_actions = ["aws:drop_established_app_layer", "aws:alert_established_app_layer"]
    stateful_rule_group_reference {
      priority     = 100
      resource_arn = aws_networkfirewall_rule_group.github.arn
    }
    route53_resolved_ip_validation {
      action                      = "DROP"
      dns_expiry_exception_policy = "DROP"
      dns_firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.this.id
      source_ip_ranges            = local.private_cidrs
      # No destination bypass ranges. An uncached address fails closed.
    }
  }
  depends_on = [aws_route53_resolver_firewall_rule_group_association.this]
}

resource "aws_networkfirewall_firewall" "this" {
  name                              = var.name
  firewall_policy_arn               = aws_networkfirewall_firewall_policy.this.arn
  vpc_id                            = aws_vpc.this.id
  delete_protection                 = true
  subnet_change_protection          = true
  firewall_policy_change_protection = true
  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall
    content { subnet_id = subnet_mapping.value.id }
  }
}

resource "aws_cloudwatch_log_group" "firewall" {
  for_each          = toset(["FLOW", "ALERT"])
  name              = "/runsecure/${var.name}/firewall/${lower(each.key)}"
  retention_in_days = 30
}
resource "aws_networkfirewall_logging_configuration" "this" {
  firewall_arn = aws_networkfirewall_firewall.this.arn
  logging_configuration {
    dynamic "log_destination_config" {
      for_each = aws_cloudwatch_log_group.firewall
      content {
        log_destination      = { logGroup = log_destination_config.value.name }
        log_destination_type = "CloudWatchLogs"
        log_type             = log_destination_config.key
      }
    }
  }
}

resource "aws_cloudwatch_log_group" "dns" {
  name              = "/runsecure/${var.name}/dns"
  retention_in_days = 30
}
resource "aws_cloudwatch_log_resource_policy" "dns" {
  policy_name = "${var.name}-dns-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "route53resolver.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.dns.arn}:*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:route53resolver:${var.region}:${data.aws_caller_identity.current.account_id}:resolver-query-log-config/*" }
      }
    }]
  })
}
resource "aws_route53_resolver_query_log_config" "this" {
  name            = var.name
  destination_arn = aws_cloudwatch_log_group.dns.arn
  depends_on      = [aws_cloudwatch_log_resource_policy.dns]
}
resource "aws_route53_resolver_query_log_config_association" "this" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.this.id
  resource_id                  = aws_vpc.this.id
}
