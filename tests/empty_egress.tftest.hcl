# Kept in its own file so it starts from empty state. aws_security_group.egress
# is Optional+Computed, so asserting that an empty rule set produces no egress
# on top of state left by an earlier run would read that run's rules instead of
# this one's configuration.

mock_provider "aws" {}

variables {
  name   = "unit-test-sg"
  vpc_id = "vpc-00000000000000000"
}

run "accepts_an_empty_egress_rule_set" {
  variables {
    egress_rules = []
  }

  assert {
    condition     = length(aws_security_group.this.egress) == 0
    error_message = "Passing egress_rules = [] must produce a security group with no egress rules."
  }
}
