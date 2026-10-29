# Platform prerequisites and limits are in docs/eks-guidebook.md.
# No GitHub App key, Kubernetes Secret value, or AWS credential enters Terraform.
locals {
  service_cidr = "172.20.0.0/16"
  cluster_arn  = "arn:aws:eks:${var.region}:${var.account_id}:cluster/${var.name}"
  platform_services = toset([
    "ec2", "ecr.api", "ecr.dkr", "eks", "eks-auth", "sts", "logs", "secretsmanager"
  ])
  node_pools = {
    management = { subnet_ids = local.management_subnet_ids, desired = 2, max = 3 }
    execution  = { subnet_ids = local.execution_subnet_ids, desired = 2, max = 4 }
  }
}

resource "aws_security_group" "nodes" {
  name_prefix = "${var.name}-nodes-"
  description = "Private node/platform transport; Pod policy is additionally mandatory."
  vpc_id      = aws_vpc.this.id
}

resource "aws_security_group" "api" {
  name_prefix = "${var.name}-api-"
  description = "Private Kubernetes API, reachable only from nodes and reviewed operators."
  vpc_id      = aws_vpc.this.id
}

resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name}-endpoints-"
  description = "Private AWS platform endpoints, not an internet exception."
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_ingress_rule" "api_nodes" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "api_operator" {
  for_each          = var.operator_cidrs
  security_group_id = aws_security_group.api.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "node_control_plane" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = 10250
  to_port                      = 10250
}

resource "aws_vpc_security_group_egress_rule" "api_kubelet" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = 10250
  to_port                      = 10250
}

resource "aws_vpc_security_group_ingress_rule" "node_internal" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "-1"
  description                  = "VPC CNI/Pod transport; namespace isolation must pass CNI acceptance before enrollment."
}

resource "aws_vpc_security_group_egress_rule" "node_internal" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "-1"
}

resource "aws_vpc_security_group_egress_rule" "node_api" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_nodes" {
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "node_https" {
  security_group_id = aws_security_group.nodes.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "Transport to private endpoints or same-AZ firewall; NOT an unrestricted internet path."
}

# VPC Resolver cannot be blocked by SG/NACL. DNS Firewall is the outer control;
# CNI policies must also prevent workload bypass of the selected cluster DNS.
resource "aws_vpc_security_group_egress_rule" "node_dns" {
  for_each          = toset(["tcp", "udp"])
  security_group_id = aws_security_group.nodes.id
  cidr_ipv4         = "${cidrhost(aws_vpc.this.cidr_block, 2)}/32"
  ip_protocol       = each.value
  from_port         = 53
  to_port           = 53
}

resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = 90
}

resource "aws_eks_cluster" "this" {
  name                          = var.name
  version                       = var.kubernetes_version
  role_arn                      = var.cluster_role_arn
  bootstrap_self_managed_addons = false
  enabled_cluster_log_types     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }
  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = local.service_cidr
  }
  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.api.id]
    subnet_ids              = local.management_subnet_ids
  }
  depends_on = [aws_cloudwatch_log_group.cluster]
}

resource "aws_eks_access_entry" "operator" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.operator_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "operator" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_eks_access_entry.operator.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}

resource "aws_vpc_endpoint" "platform" {
  for_each            = local.platform_services
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.management_subnet_ids
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.endpoints.id]
  # Not every AWS service supports endpoint policies. Authentication/role scope
  # remains required. ECR API/download policy below is explicitly constrained.
  policy = startswith(each.value, "ecr.") ? jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Principal = { AWS = aws_iam_role.nodes.arn }, Action = "ecr:GetAuthorizationToken", Resource = "*" },
      { Effect = "Allow", Principal = { AWS = aws_iam_role.nodes.arn }, Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource = sort(tolist(var.pull_repository_arns)) }
    ]
  }) : null
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat([for r in aws_route_table.management : r.id], [for r in aws_route_table.execution : r.id])
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow", Principal = "*", Action = "s3:GetObject",
      Resource = "arn:aws:s3:::prod-${var.region}-starport-layer-bucket/*"
    }]
  })
}

resource "aws_iam_role" "nodes" {
  name = "${var.name}-nodes"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "nodes" {
  role = aws_iam_role.nodes.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RequiredNodeDiscovery", Effect = "Allow",
        Action   = ["ec2:DescribeInstances", "ec2:DescribeInstanceTypes", "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets", "ec2:DescribeVolumes", "ec2:DescribeVolumesModifications", "ec2:DescribeVpcs", "eks-auth:AssumeRoleForPodIdentity"],
        Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      { Effect = "Allow", Action = "eks:DescribeCluster", Resource = local.cluster_arn },
      { Effect = "Allow", Action = "ecr:GetAuthorizationToken", Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } },
      { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource = sort(tolist(var.pull_repository_arns)) }
    ]
  })
}

resource "aws_eks_pod_identity_association" "cni" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "aws-node"
  role_arn        = var.cni_role_arn
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name  = aws_eks_cluster.this.name
  addon_name    = "vpc-cni"
  addon_version = var.addon_versions.vpc_cni
  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
    env                 = { NETWORK_POLICY_ENFORCING_MODE = "strict" }
  })
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "pod_identity" {
  cluster_name  = aws_eks_cluster.this.name
  addon_name    = "eks-pod-identity-agent"
  addon_version = var.addon_versions.pod_identity_agent
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name  = aws_eks_cluster.this.name
  addon_name    = "kube-proxy"
  addon_version = var.addon_versions.kube_proxy
}

resource "aws_launch_template" "nodes" {
  for_each               = local.node_pools
  name_prefix            = "${var.name}-${each.key}-"
  vpc_security_group_ids = [aws_security_group.nodes.id]
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_protocol_ipv6          = "disabled"
    instance_metadata_tags      = "disabled"
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs { encrypted = true }
  }
  block_device_mappings {
    device_name = "/dev/xvdb"
    ebs {
      encrypted   = true
      volume_type = "gp3"
      volume_size = 80
    }
  }
  user_data = base64encode(<<-TOML
    [settings.kubernetes]
    pod-pids-limit = 256
    seccomp-default = true
    [settings.kubernetes.node-labels]
    "runsecure.io/pool" = "${each.key}"
    [settings.host-containers.admin]
    enabled = false
    [settings.host-containers.control]
    enabled = false
  TOML
  )
}

resource "aws_eks_node_group" "nodes" {
  for_each        = local.node_pools
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.name}-${each.key}"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = each.value.subnet_ids
  ami_type        = "BOTTLEROCKET_ARM_64"
  version         = var.kubernetes_version
  release_version = var.bottlerocket_release_version
  instance_types  = [var.instance_type]
  capacity_type   = "ON_DEMAND"
  labels          = { "runsecure.io/pool" = each.key }
  dynamic "taint" {
    for_each = each.key == "execution" ? [1] : []
    content {
      key    = "dedicated"
      value  = "runsecure-execution"
      effect = "NO_SCHEDULE"
    }
  }
  scaling_config {
    desired_size = each.value.desired
    min_size     = each.value.desired
    max_size     = each.value.max
  }
  update_config { max_unavailable = 1 }
  launch_template {
    id      = aws_launch_template.nodes[each.key].id
    version = aws_launch_template.nodes[each.key].latest_version
  }
  depends_on = [
    aws_iam_role_policy.nodes, aws_vpc_endpoint.platform, aws_vpc_endpoint.s3,
    aws_eks_addon.vpc_cni, aws_eks_addon.pod_identity, aws_eks_addon.kube_proxy,
    aws_eks_pod_identity_association.cni,
    aws_networkfirewall_firewall.this,
    aws_route53_resolver_firewall_rule_group_association.this,
    aws_route_table_association.management, aws_route_table_association.execution,
    aws_route_table_association.firewall, aws_route_table_association.public,
    aws_networkfirewall_logging_configuration.this,
    aws_route53_resolver_query_log_config_association.this
  ]
}

# CoreDNS is intentionally NOT installed here. Strict CNI policy needs its
# ingress/upstream/API policies before the add-on can become healthy. Stage it
# through private operator access after reviewing the platform policy example.
output "coredns_staged_version" { value = var.addon_versions.coredns }

output "private_cluster_endpoint" { value = aws_eks_cluster.this.endpoint }
output "runtime_enrollment" {
  value = "BLOCKED until target-cluster acceptance in docs/eks-guidebook.md passes. Terraform does not install Helm, enroll repositories, or read App keys."
}
