variable "name" {
  description = "Name of the security group."
  type        = string
}

variable "description" {
  description = "Description of the security group."
  type        = string
  default     = "Managed by Terraform"
}

variable "vpc_id" {
  description = "ID of the VPC in which to create the security group."
  type        = string
}

variable "ingress_rules" {
  description = "List of ingress rules to apply to the security group. Defaults to no ingress at all."
  type = list(object({
    description = optional(string, "")
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = optional(list(string), [])
  }))
  default = []

  validation {
    condition     = alltrue([for rule in var.ingress_rules : length(rule.cidr_blocks) > 0])
    error_message = "Every ingress rule must list at least one entry in cidr_blocks; this module exposes no other source type, and a rule without a source is rejected by the EC2 API."
  }

  # Only TCP and UDP rules carry real port numbers. For icmp/icmpv6 these fields
  # are the ICMP type and code (and -1 means "all"), so they are left alone.
  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.from_port >= 0 && rule.to_port <= 65535 && rule.from_port <= rule.to_port
      if contains(["tcp", "6", "udp", "17"], lower(rule.protocol))
    ])
    error_message = "Every TCP or UDP ingress rule must satisfy 0 <= from_port <= to_port <= 65535."
  }
}

variable "egress_rules" {
  description = "List of egress rules to apply to the security group. Defaults to allowing all outbound traffic, matching the behaviour of a security group created outside this module. Pass an explicit list to restrict it, or [] to allow no egress at all."
  type = list(object({
    description = optional(string, "")
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = optional(list(string), ["0.0.0.0/0"])
  }))
  default = [{
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }]

  validation {
    condition     = alltrue([for rule in var.egress_rules : length(rule.cidr_blocks) > 0])
    error_message = "Every egress rule must list at least one entry in cidr_blocks; this module exposes no other destination type, and a rule without a destination is rejected by the EC2 API."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      rule.from_port >= 0 && rule.to_port <= 65535 && rule.from_port <= rule.to_port
      if contains(["tcp", "6", "udp", "17"], lower(rule.protocol))
    ])
    error_message = "Every TCP or UDP egress rule must satisfy 0 <= from_port <= to_port <= 65535."
  }
}

variable "guarded_ingress_ports" {
  description = "Ports that this module refuses to expose to the whole internet unless allow_public_guarded_ingress is set to true. Defaults to the usual remote-administration and database ports. Set to [] to disable the guard entirely."
  type        = list(number)
  default = [
    22,    # SSH
    23,    # Telnet
    135,   # MSRPC
    445,   # SMB
    1433,  # Microsoft SQL Server
    1521,  # Oracle
    2049,  # NFS
    3306,  # MySQL / MariaDB
    3389,  # RDP
    5432,  # PostgreSQL
    5601,  # Kibana
    5672,  # AMQP / RabbitMQ
    5985,  # WinRM (HTTP)
    5986,  # WinRM (HTTPS)
    6379,  # Redis
    9042,  # Cassandra
    9200,  # Elasticsearch / OpenSearch
    11211, # Memcached
    27017, # MongoDB
  ]

  validation {
    condition     = alltrue([for port in var.guarded_ingress_ports : port >= 0 && port <= 65535])
    error_message = "Every entry in guarded_ingress_ports must be between 0 and 65535."
  }
}

variable "allow_public_guarded_ingress" {
  description = "Set to true to acknowledge and permit ingress rules that open a port in guarded_ingress_ports to an unrestricted CIDR such as 0.0.0.0/0. Left false, such a rule fails the plan instead of silently exposing the port."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to the security group."
  type        = map(string)
  default     = {}
}
