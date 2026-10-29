# Every run is a MOCKED PLAN. No AWS credentials or infrastructure are used.
mock_provider "aws" {
  override_during = plan
  mock_data "aws_network_interface" { defaults = { private_ip = "10.80.0.8" } }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_resource "aws_eks_cluster" {
    defaults = { endpoint = "https://fixture.cluster.eks.amazonaws.com" }
  }
  mock_resource "aws_vpc_endpoint" {
    defaults = { dns_entry = [{ dns_name = "fixture.vpce.amazonaws.com", hosted_zone_id = "ZFIXTURE" }], network_interface_ids = ["eni-aaaaaaaa", "eni-bbbbbbbb"] }
  }
  mock_resource "aws_networkfirewall_firewall" {
    defaults = {
      arn = "arn:aws:network-firewall:us-east-2:123456789012:firewall/fixture"
      firewall_status = [{
        sync_states = [
          { availability_zone = "us-east-2a", attachment = [{ endpoint_id = "vpce-aaaaaaaa", subnet_id = "subnet-aaaaaaaa", status = "READY" }] },
          { availability_zone = "us-east-2b", attachment = [{ endpoint_id = "vpce-bbbbbbbb", subnet_id = "subnet-bbbbbbbb", status = "READY" }] }
        ]
      }]
    }
  }
  mock_resource "aws_networkfirewall_rule_group" {
    defaults = { arn = "arn:aws:network-firewall:us-east-2:123456789012:stateful-rulegroup/fixture" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-2:123456789012:log-group:/fixture" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/fixture-node" }
  }
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
  addon_versions = {
    vpc_cni            = "v1.21.0-eksbuild.1"
    pod_identity_agent = "v1.3.0-eksbuild.1"
    kube_proxy         = "v1.36.0-eksbuild.1"
    coredns            = "v1.12.0-eksbuild.1"
  }
}

run "quarantined_default_and_private_platform" {
  command = plan
  assert {
    condition     = aws_eks_cluster.this.vpc_config[0].endpoint_private_access && !aws_eks_cluster.this.vpc_config[0].endpoint_public_access
    error_message = "Kubernetes API must remain private-only."
  }
  assert {
    condition     = length(local.github_rules) == 1 && strcontains(local.github_rules[0], "Management GitHub API")
    error_message = "No execution internet pass rule may exist before explicit hostname enrollment."
  }
  assert {
    condition     = aws_networkfirewall_firewall_policy.this.firewall_policy[0].route53_resolved_ip_validation[0].action == "DROP" && aws_networkfirewall_firewall_policy.this.firewall_policy[0].route53_resolved_ip_validation[0].dns_expiry_exception_policy == "DROP"
    error_message = "Missing/expired resolved-IP evidence must fail closed."
  }
  assert {
    condition     = length(aws_networkfirewall_firewall_policy.this.firewall_policy[0].route53_resolved_ip_validation[0].source_ip_ranges) == 4 && try(length(aws_networkfirewall_firewall_policy.this.firewall_policy[0].route53_resolved_ip_validation[0].bypass_destination_validation_ip_ranges), 0) == 0
    error_message = "Cover all private sources without destination-validation bypass ranges."
  }
  assert {
    condition     = aws_networkfirewall_firewall_policy.this.firewall_policy[0].stateless_default_actions == toset(["aws:drop"]) && aws_networkfirewall_firewall_policy.this.firewall_policy[0].stateless_fragment_default_actions == toset(["aws:drop"])
    error_message = "Other protocols and fragments cannot bypass stateful inspection."
  }
  assert {
    condition     = alltrue([for az, table in aws_route_table.execution : alltrue([for route in table.route : route.vpc_endpoint_id == local.firewall_endpoint_ids[az] && route.nat_gateway_id == null])])
    error_message = "Execution default routes must use their own AZ firewall, never NAT directly."
  }
  assert {
    condition     = alltrue([for az, table in aws_route_table.management : alltrue([for route in table.route : route.vpc_endpoint_id == local.firewall_endpoint_ids[az] && route.nat_gateway_id == null])])
    error_message = "Management default routes must use their own AZ firewall."
  }
  assert {
    condition     = alltrue([for az, table in aws_route_table.public : length([for route in table.route : route if route.vpc_endpoint_id == local.firewall_endpoint_ids[az]]) == 2])
    error_message = "Both private return paths must traverse the same AZ firewall."
  }
  assert {
    condition     = aws_route53_resolver_firewall_config.this.firewall_fail_open == "DISABLED" && aws_route53_resolver_firewall_rule.allowed.firewall_domain_redirection_action == "INSPECT_REDIRECTION_DOMAIN" && aws_route53_resolver_firewall_rule.blocked.action == "BLOCK"
    error_message = "DNS failures and unreviewed redirects must not silently open egress."
  }
  assert {
    condition     = alltrue([for node in aws_eks_node_group.nodes : node.ami_type == "BOTTLEROCKET_ARM_64"]) && alltrue([for lt in aws_launch_template.nodes : lt.metadata_options[0].http_tokens == "required" && lt.metadata_options[0].http_put_response_hop_limit == 1 && lt.metadata_options[0].http_protocol_ipv6 == "disabled"])
    error_message = "All pools must use Bottlerocket ARM64 and restrictive metadata options."
  }
  assert {
    condition     = alltrue([for lt in aws_launch_template.nodes : strcontains(base64decode(lt.user_data), "pod-pids-limit = 256") && strcontains(base64decode(lt.user_data), "[settings.host-containers.admin]\nenabled = false") && strcontains(base64decode(lt.user_data), "[settings.host-containers.control]\nenabled = false")])
    error_message = "Node PIDs must be bounded and both host containers disabled."
  }
  assert {
    condition     = jsondecode(aws_eks_addon.vpc_cni.configuration_values).env.NETWORK_POLICY_ENFORCING_MODE == "strict" && jsondecode(aws_eks_addon.vpc_cni.configuration_values).enableNetworkPolicy == "true"
    error_message = "Do not introduce the standard-mode initial default-allow window."
  }
  assert {
    condition     = toset(jsondecode(aws_iam_role_policy.nodes.policy).Statement[3].Resource) == var.pull_repository_arns && alltrue(flatten([for s in jsondecode(aws_iam_role_policy.nodes.policy).Statement : [for a in try(tolist(s.Action), [s.Action]) : !strcontains(a, "*")]]))
    error_message = "Node downloads must be repository scoped and IAM actions explicitly named."
  }
}

run "exact_name_and_dns_identity_are_both_required" {
  command = plan
  variables { github_execution_domains = ["github.com", "codeload.github.com"] }
  assert {
    condition = length(local.github_rules) == 3 && alltrue([
      for domain in var.github_execution_domains : anytrue([
        for rule in local.github_rules : strcontains(rule, "content:\"${domain}\"") && strcontains(rule, "aws_route_53_resolved_domain:\"${domain}\"") && strcontains(rule, "startswith; endswith;") && strcontains(rule, "flow:to_server,established") && strcontains(rule, "-> $EXTERNAL_NET 443")
      ])
    ])
    error_message = "A GitHub pass requires the exact SNI and matching DNS-derived destination in the SAME rule."
  }
}

run "reject_wildcard_github_or_storage" {
  command = plan
  variables { github_execution_domains = ["*.blob.core.windows.net"] }
  expect_failures = [var.github_execution_domains]
}

run "reject_non_github_internet_host" {
  command = plan
  variables { github_execution_domains = ["api.openai.com"] }
  expect_failures = [var.github_execution_domains]
}

run "reject_injected_rule_text" {
  command = plan
  variables { github_execution_domains = ["github.com\"; sid:1;)\npass ip any any -> any any"] }
  expect_failures = [var.github_execution_domains]
}

run "reject_wildcard_private_dns_exception" {
  command = plan
  variables { additional_platform_dns_domains = ["*.amazonaws.com"] }
  expect_failures = [var.additional_platform_dns_domains]
}

run "reject_global_image_download_scope" {
  command = plan
  variables { pull_repository_arns = ["*"] }
  expect_failures = [var.pull_repository_arns]
}

run "reject_public_operator_access" {
  command = plan
  variables { operator_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.operator_cidrs]
}

run "reject_overlapping_subnets" {
  command = plan
  variables {
    zones = {
      us-east-2a = { management_cidr = "10.80.0.0/24", execution_cidr = "10.80.0.0/20", firewall_cidr = "10.80.240.0/28", public_cidr = "10.80.242.0/24" }
      us-east-2b = { management_cidr = "10.80.1.0/24", execution_cidr = "10.80.32.0/20", firewall_cidr = "10.80.240.16/28", public_cidr = "10.80.243.0/24" }
    }
  }
  expect_failures = [aws_vpc.this]
}

run "reject_outside_vpc_subnet" {
  command = plan
  variables {
    zones = {
      us-east-2a = { management_cidr = "10.81.0.0/24", execution_cidr = "10.80.16.0/20", firewall_cidr = "10.80.240.0/28", public_cidr = "10.80.242.0/24" }
      us-east-2b = { management_cidr = "10.80.1.0/24", execution_cidr = "10.80.32.0/20", firewall_cidr = "10.80.240.16/28", public_cidr = "10.80.243.0/24" }
    }
  }
  expect_failures = [aws_vpc.this]
}

run "reject_public_addressed_vpc" {
  command = plan
  variables {
    vpc_cidr = "11.80.0.0/16"
    zones = {
      us-east-2a = { management_cidr = "11.80.0.0/24", execution_cidr = "11.80.16.0/20", firewall_cidr = "11.80.240.0/28", public_cidr = "11.80.242.0/24" }
      us-east-2b = { management_cidr = "11.80.1.0/24", execution_cidr = "11.80.32.0/20", firewall_cidr = "11.80.240.16/28", public_cidr = "11.80.243.0/24" }
    }
  }
  expect_failures = [aws_vpc.this]
}

run "reject_service_network_overlap" {
  command = plan
  variables {
    vpc_cidr = "172.20.0.0/16"
    zones = {
      us-east-2a = { management_cidr = "172.20.0.0/24", execution_cidr = "172.20.16.0/20", firewall_cidr = "172.20.240.0/28", public_cidr = "172.20.242.0/24" }
      us-east-2b = { management_cidr = "172.20.1.0/24", execution_cidr = "172.20.32.0/20", firewall_cidr = "172.20.240.16/28", public_cidr = "172.20.243.0/24" }
    }
  }
  expect_failures = [aws_vpc.this]
}
