variable "name" {
  type    = string
  default = "runsecure-example"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,29}$", var.name))
    error_message = "Use a short lowercase infrastructure name."
  }
}

variable "region" {
  type    = string
  default = "us-east-2"
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.region))
    error_message = "Use a commercial AWS region; this example does not implement other partitions."
  }
}

variable "account_id" {
  description = "Explicit intended AWS account; prevents accidentally using another signed-in account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Set the reviewed 12-digit account ID."
  }
}

variable "kubernetes_version" {
  description = "Select and qualify an EKS/Bottlerocket/add-on compatible minor version; never infer compatibility from latest."
  type        = string
  validation {
    condition     = can(regex("^1\\.[0-9]{2}$", var.kubernetes_version))
    error_message = "Set an exact Kubernetes minor version such as 1.36."
  }
}

variable "bottlerocket_release_version" {
  description = "Exact EKS Bottlerocket ARM64 release identifier qualified for kubernetes_version. No moving recommended AMI lookup."
  type        = string
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+-[a-z0-9]+$", var.bottlerocket_release_version))
    error_message = "Set the exact qualified Bottlerocket release version, including its release suffix."
  }
}

variable "cluster_role_arn" {
  description = "Pre-reviewed EKS control-plane service role. This example does not grant that role new permissions."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::${var.account_id}:role/.+$", var.cluster_role_arn))
    error_message = "Supply an explicit reviewed EKS service-role ARN."
  }
}

variable "cni_role_arn" {
  description = "Pre-reviewed IPv4 CNI-only Pod Identity role; trust must restrict cluster/namespace/service-account as documented."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::${var.account_id}:role/.+$", var.cni_role_arn))
    error_message = "Supply an explicit reviewed CNI role ARN."
  }
}

variable "operator_role_arn" {
  description = "Existing tightly controlled bootstrap/operator role. Gets explicit cluster-admin access, never assigned to a runner."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.operator_role_arn))
    error_message = "Supply an explicit reviewed operator role ARN."
  }
}

variable "operator_cidrs" {
  description = "Private VPN/Direct Connect administration source CIDRs; no public API or SSH ingress is created."
  type        = set(string)
  validation {
    condition = length(var.operator_cidrs) > 0 && alltrue([
      for c in var.operator_cidrs : can(cidrnetmask(c)) &&
      (startswith(c, "10.") || startswith(c, "192.168.") || can(regex("^172\\.(1[6-9]|2[0-9]|3[01])\\.", c))) &&
      try(tonumber(split("/", c)[1]) >= 16, false)
    ])
    error_message = "Supply bounded private IPv4 administration CIDRs (/16 or narrower)."
  }
}

variable "pull_repository_arns" {
  description = "Exact pre-existing private ECR repositories for mirrored RunSecure AND required platform/add-on images; no pull-through first-miss internet fallback."
  type        = set(string)
  validation {
    condition = length(var.pull_repository_arns) > 0 && alltrue([
      for a in var.pull_repository_arns : can(regex("^arn:aws:ecr:${var.region}:[0-9]{12}:repository/[a-z0-9._/-]+$", a))
    ])
    error_message = "List exact ECR repository ARNs without wildcard grants."
  }
}

variable "addon_versions" {
  description = "Explicit versions verified with describe-addon-versions for the selected EKS minor and ARM64."
  type = object({
    vpc_cni            = string
    pod_identity_agent = string
    kube_proxy         = string
    coredns            = string
  })
  validation {
    condition     = alltrue([for v in values(var.addon_versions) : can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+-eksbuild\\.[0-9]+$", v))]) && can(regex("^v(1\\.(2[1-9]|[3-9][0-9])|[2-9]\\.)", var.addon_versions.vpc_cni))
    error_message = "Pin every add-on; this example requires VPC CNI >=1.21 and target-version compatibility verification."
  }
}

variable "instance_type" {
  type    = string
  default = "m8g.xlarge"
  validation {
    condition     = can(regex("^[a-z][0-9]+g[a-z]*\\.[a-z0-9]+$", var.instance_type))
    error_message = "Select a qualified ARM64 Graviton instance family."
  }
}
