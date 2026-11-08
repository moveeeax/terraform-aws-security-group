# Non-CIDR sources and destinations: other security groups, managed prefix
# lists and self. Plan-only, against a mocked provider.

mock_provider "aws" {}

variables {
  name   = "unit-test-sg"
  vpc_id = "vpc-00000000000000000"
}

run "cidr_only_rules_plan_as_before" {
  command = plan

  variables {
    ingress_rules = [{
      description = "HTTPS"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8"]
    }]
  }

  assert {
    condition     = one(aws_security_group.this.ingress).cidr_blocks == tolist(["10.0.0.0/8"])
    error_message = "A CIDR-only ingress rule must keep its cidr_blocks."
  }

  assert {
    condition = (
      length(one(aws_security_group.this.ingress).security_groups) == 0 &&
      length(one(aws_security_group.this.ingress).prefix_list_ids) == 0 &&
      one(aws_security_group.this.ingress).self == false
    )
    error_message = "A CIDR-only ingress rule must not gain security group, prefix list or self sources."
  }

  assert {
    condition     = one(aws_security_group.this.egress).cidr_blocks == tolist(["0.0.0.0/0"])
    error_message = "The default egress rule must still allow all outbound IPv4 traffic."
  }

  assert {
    condition     = length(one(aws_security_group.this.egress).security_groups) == 0 && one(aws_security_group.this.egress).self == false
    error_message = "The default egress rule must not gain security group or self destinations."
  }
}

run "egress_rule_without_cidr_blocks_still_defaults_to_the_internet" {
  command = plan

  variables {
    egress_rules = [{
      from_port = 443
      to_port   = 443
      protocol  = "tcp"
    }]
  }

  assert {
    condition     = one(aws_security_group.this.egress).cidr_blocks == tolist(["0.0.0.0/0"])
    error_message = "An egress rule that names no destination kind must keep the historical 0.0.0.0/0 fallback."
  }
}

run "accepts_a_security_group_source" {
  command = plan

  variables {
    ingress_rules = [{
      description     = "PostgreSQL from the app tier"
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = ["sg-0123456789abcdef0"]
    }]
  }

  assert {
    condition     = contains(one(aws_security_group.this.ingress).security_groups, "sg-0123456789abcdef0")
    error_message = "security_groups must be passed through to the ingress rule."
  }

  assert {
    condition     = length(one(aws_security_group.this.ingress).cidr_blocks) == 0
    error_message = "A security-group-only ingress rule must not carry any CIDR."
  }
}

run "accepts_a_prefix_list_source" {
  command = plan

  variables {
    ingress_rules = [{
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = ["pl-0123456789abcdef0"]
    }]
  }

  assert {
    condition     = one(aws_security_group.this.ingress).prefix_list_ids == tolist(["pl-0123456789abcdef0"])
    error_message = "prefix_list_ids must be passed through to the ingress rule."
  }
}

run "accepts_a_self_source" {
  command = plan

  variables {
    ingress_rules = [{
      description = "Cluster members talk to each other"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      self        = true
    }]
  }

  assert {
    condition     = one(aws_security_group.this.ingress).self == true
    error_message = "self must be passed through to the ingress rule."
  }
}

run "self_source_does_not_trip_the_public_exposure_guard" {
  command = plan

  variables {
    ingress_rules = [{
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      security_groups = ["sg-0123456789abcdef0"]
      self            = true
    }]
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1
    error_message = "SSH from a security group or self is not internet exposure and must be accepted."
  }
}

run "guard_still_catches_a_world_cidr_mixed_with_a_security_group" {
  command = plan

  variables {
    ingress_rules = [{
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      security_groups = ["sg-0123456789abcdef0"]
      cidr_blocks     = ["0.0.0.0/0"]
    }]
  }

  expect_failures = [aws_security_group.this]
}

run "egress_to_a_security_group_does_not_also_open_the_internet" {
  command = plan

  variables {
    egress_rules = [{
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = ["sg-0123456789abcdef0"]
    }]
  }

  assert {
    condition     = length(one(aws_security_group.this.egress).cidr_blocks) == 0
    error_message = "An egress rule to a security group must not fall back to 0.0.0.0/0."
  }

  assert {
    condition     = contains(one(aws_security_group.this.egress).security_groups, "sg-0123456789abcdef0")
    error_message = "security_groups must be passed through to the egress rule."
  }
}

run "egress_to_a_prefix_list_with_explicit_cidr_keeps_both" {
  command = plan

  variables {
    egress_rules = [{
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = ["pl-0123456789abcdef0"]
      cidr_blocks     = ["10.0.0.0/8"]
    }]
  }

  assert {
    condition     = one(aws_security_group.this.egress).cidr_blocks == tolist(["10.0.0.0/8"])
    error_message = "An explicit cidr_blocks must be kept alongside other destinations."
  }

  assert {
    condition     = one(aws_security_group.this.egress).prefix_list_ids == tolist(["pl-0123456789abcdef0"])
    error_message = "prefix_list_ids must be passed through to the egress rule."
  }
}

run "rejects_a_malformed_security_group_id" {
  command = plan

  variables {
    ingress_rules = [{
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      security_groups = ["app-tier"]
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_a_malformed_prefix_list_id" {
  command = plan

  variables {
    ingress_rules = [{
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = ["com.amazonaws.us-east-1.s3"]
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_ingress_rule_with_self_false_and_no_other_source" {
  command = plan

  variables {
    ingress_rules = [{
      from_port = 443
      to_port   = 443
      protocol  = "tcp"
      self      = false
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_malformed_ids_in_egress" {
  command = plan

  variables {
    egress_rules = [{
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      security_groups = ["sg-XYZ"]
    }]
  }

  expect_failures = [var.egress_rules]
}

run "rejects_egress_rule_with_every_destination_empty" {
  command = plan

  variables {
    egress_rules = [{
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      cidr_blocks     = []
      security_groups = []
    }]
  }

  expect_failures = [var.egress_rules]
}

run "accepts_an_account_prefixed_security_group_id" {
  command = plan

  variables {
    ingress_rules = [{
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      security_groups = ["111122223333/sg-0123456789abcdef0"]
    }]
  }

  assert {
    condition     = contains(one(aws_security_group.this.ingress).security_groups, "111122223333/sg-0123456789abcdef0")
    error_message = "A security group in a peered VPC, referenced as account/sg-id, must be accepted."
  }
}
