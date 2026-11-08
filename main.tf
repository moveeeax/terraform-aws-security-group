locals {
  # Protocol values for which from_port/to_port really are TCP/UDP port numbers.
  # For icmp and friends those fields carry type/code instead, so the port guard
  # below must not treat them as ports.
  port_based_protocols = ["tcp", "6", "udp", "17"]

  # Protocol values that mean "every protocol on every port".
  all_protocols = ["-1", "all"]

  # Resolve the egress cidr_blocks fallback. An omitted cidr_blocks used to mean
  # ["0.0.0.0/0"] unconditionally, and still does for rules that only use CIDRs,
  # so existing configurations plan exactly as before. A rule that targets a
  # security group, a prefix list or self falls back to [] instead.
  egress_rules = [
    for rule in var.egress_rules : merge(rule, {
      cidr_blocks = rule.cidr_blocks != null ? rule.cidr_blocks : (
        rule.self || length(rule.security_groups) + length(rule.prefix_list_ids) > 0 ? [] : ["0.0.0.0/0"]
      )
    })
  ]

  # Ingress rules that would open a guarded port to the entire internet. A CIDR
  # with a /0 prefix (0.0.0.0/0, ::/0) covers every address, so it is the marker
  # for "unrestricted". Both IPv4 (cidr_blocks) and IPv6 (ipv6_cidr_blocks)
  # sources are checked; either one alone is enough to trigger the guard.
  public_guarded_ingress = [
    for rule in var.ingress_rules :
    format("%s %d-%d from %s", rule.protocol, rule.from_port, rule.to_port, join(",", concat(rule.cidr_blocks, rule.ipv6_cidr_blocks)))
    if length(var.guarded_ingress_ports) > 0 &&
    anytrue([for cidr in concat(rule.cidr_blocks, rule.ipv6_cidr_blocks) : endswith(cidr, "/0")]) && (
      contains(local.all_protocols, lower(rule.protocol)) || (
        contains(local.port_based_protocols, lower(rule.protocol)) &&
        anytrue([for port in var.guarded_ingress_ports : port >= rule.from_port && port <= rule.to_port])
      )
    )
  ]
}

resource "aws_security_group" "this" {
  name        = var.name
  description = var.description
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      description      = ingress.value.description
      from_port        = ingress.value.from_port
      to_port          = ingress.value.to_port
      protocol         = ingress.value.protocol
      cidr_blocks      = ingress.value.cidr_blocks
      ipv6_cidr_blocks = ingress.value.ipv6_cidr_blocks
      security_groups  = ingress.value.security_groups
      prefix_list_ids  = ingress.value.prefix_list_ids
      self             = ingress.value.self
    }
  }

  dynamic "egress" {
    for_each = local.egress_rules
    content {
      description      = egress.value.description
      from_port        = egress.value.from_port
      to_port          = egress.value.to_port
      protocol         = egress.value.protocol
      cidr_blocks      = egress.value.cidr_blocks
      ipv6_cidr_blocks = egress.value.ipv6_cidr_blocks
      security_groups  = egress.value.security_groups
      prefix_list_ids  = egress.value.prefix_list_ids
      self             = egress.value.self
    }
  }

  tags = merge({ Name = var.name }, var.tags)

  lifecycle {
    precondition {
      condition = var.allow_public_guarded_ingress || length(local.public_guarded_ingress) == 0
      error_message = join(" ", [
        "Refusing to expose a guarded port to an unrestricted CIDR.",
        "Offending ingress rules: ${join("; ", local.public_guarded_ingress)}.",
        "Narrow cidr_blocks to the networks that actually need access, remove the port from",
        "guarded_ingress_ports, or set allow_public_guarded_ingress = true to accept the exposure.",
      ])
    }
  }
}
