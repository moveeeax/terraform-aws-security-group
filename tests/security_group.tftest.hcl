# Requires Terraform >= 1.7 (or OpenTofu >= 1.7) for mock_provider. The module
# itself still only requires >= 1.5 — this is a test-only requirement, so do not
# raise required_version in versions.tf on account of it.
#
# Runs entirely offline: the provider is mocked, so no credentials and no
# network access are needed.

mock_provider "aws" {}

variables {
  name   = "unit-test-sg"
  vpc_id = "vpc-00000000000000000"
}

run "defaults_create_no_ingress" {
  assert {
    condition     = length(aws_security_group.this.ingress) == 0
    error_message = "The module must not create any ingress rule unless the caller asks for one."
  }
}

run "defaults_allow_all_egress" {
  assert {
    condition     = length(aws_security_group.this.egress) == 1
    error_message = "The default egress rule set must contain exactly one rule."
  }

  assert {
    condition     = one(aws_security_group.this.egress).protocol == "-1"
    error_message = "The default egress rule must allow every protocol."
  }

  assert {
    condition     = contains(one(aws_security_group.this.egress).cidr_blocks, "0.0.0.0/0")
    error_message = "The default egress rule must allow all outbound IPv4 traffic."
  }
}

run "name_tag_is_set_and_overridable" {
  variables {
    tags = { Environment = "test" }
  }

  assert {
    condition     = aws_security_group.this.tags["Name"] == "unit-test-sg"
    error_message = "The security group must carry a Name tag derived from var.name."
  }

  assert {
    condition     = aws_security_group.this.tags["Environment"] == "test"
    error_message = "Caller-supplied tags must be merged in."
  }
}

# --- the public-exposure guard -----------------------------------------------

run "rejects_world_open_ssh" {
  command = plan

  variables {
    ingress_rules = [{
      description = "SSH from anywhere"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }]
  }

  expect_failures = [aws_security_group.this]
}

run "rejects_world_open_rdp_via_ipv6" {
  command = plan

  variables {
    ingress_rules = [{
      from_port        = 3389
      to_port          = 3389
      protocol         = "tcp"
      ipv6_cidr_blocks = ["::/0"]
    }]
  }

  expect_failures = [aws_security_group.this]
}

run "rejects_guarded_port_open_to_mixed_ipv4_and_ipv6" {
  command = plan

  variables {
    ingress_rules = [{
      description      = "SSH from a private IPv4 range but wide open over IPv6"
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      cidr_blocks      = ["10.0.0.0/8"]
      ipv6_cidr_blocks = ["::/0"]
    }]
  }

  expect_failures = [aws_security_group.this]
}

run "allows_guarded_port_from_a_private_ipv6_cidr" {
  variables {
    ingress_rules = [{
      description      = "SSH from an internal IPv6 range"
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      ipv6_cidr_blocks = ["fd00::/8"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "A guarded port restricted to a private IPv6 CIDR must be accepted."
  }
}

run "rejects_guarded_port_inside_a_wide_range" {
  command = plan

  variables {
    ingress_rules = [{
      description = "A range that happens to swallow PostgreSQL"
      from_port   = 5000
      to_port     = 6000
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
    }]
  }

  expect_failures = [aws_security_group.this]
}

run "rejects_world_open_all_protocols" {
  command = plan

  variables {
    ingress_rules = [{
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }]
  }

  expect_failures = [aws_security_group.this]
}

run "allows_guarded_port_from_a_private_cidr" {
  variables {
    ingress_rules = [{
      description = "SSH from the bastion subnet"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["10.0.1.0/24"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "A guarded port restricted to a private CIDR must be accepted."
  }
}

run "allows_world_open_https" {
  variables {
    ingress_rules = [{
      description = "HTTPS"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "Ports outside guarded_ingress_ports must be openable to the internet."
  }
}

run "allows_world_open_ssh_with_explicit_opt_in" {
  variables {
    allow_public_guarded_ingress = true
    ingress_rules = [{
      description = "SSH from anywhere, deliberately"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "allow_public_guarded_ingress = true must let the exposure through."
  }
}

run "guard_ignores_icmp_type_and_code" {
  variables {
    ingress_rules = [{
      description = "All ICMP from anywhere; -1/-1 is type/code, not a port range"
      from_port   = -1
      to_port     = -1
      protocol    = "icmp"
      cidr_blocks = ["0.0.0.0/0"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "ICMP type/code must not be mistaken for a TCP/UDP port range."
  }
}

run "empty_guard_list_disables_the_guard" {
  variables {
    guarded_ingress_ports = []
    ingress_rules = [{
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "An empty guarded_ingress_ports must disable the guard."
  }
}

# --- input validation --------------------------------------------------------

run "rejects_ingress_rule_without_a_source" {
  command = plan

  variables {
    ingress_rules = [{
      description = "Neither cidr_blocks nor ipv6_cidr_blocks set"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "accepts_ingress_rule_with_only_an_ipv6_source" {
  variables {
    ingress_rules = [{
      description      = "HTTPS over IPv6 only, no cidr_blocks at all"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      ipv6_cidr_blocks = ["2001:db8::/32"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "A rule that supplies only ipv6_cidr_blocks must be accepted; ipv6_cidr_blocks is a valid source on its own."
  }
}

run "rejects_inverted_ingress_port_range" {
  command = plan

  variables {
    ingress_rules = [{
      from_port   = 8080
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8"]
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_out_of_range_ingress_port" {
  command = plan

  variables {
    ingress_rules = [{
      from_port   = 80
      to_port     = 70000
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8"]
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_egress_rule_without_a_destination" {
  command = plan

  variables {
    egress_rules = [{
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = []
    }]
  }

  expect_failures = [var.egress_rules]
}

run "accepts_egress_rule_with_only_an_ipv6_destination" {
  variables {
    egress_rules = [{
      description      = "Egress restricted to an internal IPv6 range only"
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = []
      ipv6_cidr_blocks = ["fd00::/8"]
    }]
  }

  assert {
    condition     = length(aws_security_group.this.egress) == 1
    error_message = "An egress rule that supplies only ipv6_cidr_blocks must be accepted."
  }
}

