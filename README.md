# terraform-aws-security-group

Terraform module that manages an [Amazon VPC](https://aws.amazon.com/vpc/)
security group. It creates a single security group and renders ingress and
egress rules from list-of-object variables, so callers can declare their rule
set inline without touching the resource.

## Usage

```hcl
module "security_group" {
  source = "github.com/moveeeax/terraform-aws-security-group"

  name   = "web-sg"
  vpc_id = "vpc-0abc123"

  ingress_rules = [
    {
      description = "HTTPS"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

A runnable example lives in [`examples/basic`](examples/basic).

## IPv4 and IPv6 sources

Each rule accepts `cidr_blocks` for IPv4 CIDRs and a separate `ipv6_cidr_blocks`
for IPv6 CIDRs, matching the two distinct fields the `aws_security_group`
resource itself exposes. Putting an IPv6 CIDR such as `::/0` into `cidr_blocks`
is rejected by the AWS API at apply time, so use the right field for the
address family:

```hcl
ingress_rules = [
  {
    description      = "HTTPS from anywhere, v4 and v6"
    from_port        = 443
    to_port           = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
]
```

A rule needs at least one entry across the two fields; both default to `[]`.

## Public exposure guard

The module creates **no ingress rules by default**. On top of that, it refuses
to plan an ingress rule that opens a remote-administration or database port to
an unrestricted CIDR (any block with a `/0` prefix, such as `0.0.0.0/0` in
`cidr_blocks` or `::/0` in `ipv6_cidr_blocks`). The guarded set is
`var.guarded_ingress_ports` and defaults to 22, 23, 135, 445, 1433, 1521, 2049,
3306, 3389, 5432, 5601, 5672, 5985, 5986, 6379, 9042, 9200, 11211 and 27017.

The check catches a guarded port however it is reached — named directly, wrapped
inside a wider `from_port`/`to_port` range, covered by `protocol = "-1"`, or
exposed over IPv6 rather than IPv4:

```
Error: Resource precondition failed

Refusing to expose a guarded port to an unrestricted CIDR. Offending ingress
rules: tcp 22-22 from 0.0.0.0/0. Narrow cidr_blocks to the networks that
actually need access, remove the port from guarded_ingress_ports, or set
allow_public_guarded_ingress = true to accept the exposure.
```

There are three ways past it, in descending order of preference: narrow
`cidr_blocks`/`ipv6_cidr_blocks`, drop the port from `guarded_ingress_ports`, or
opt out wholesale with `allow_public_guarded_ingress = true`. ICMP rules are
exempt because their `from_port`/`to_port` carry an ICMP type and code rather
than ports.

Egress still defaults to allow-all outbound IPv4, matching what AWS gives a
security group created without any egress block. Pass an explicit
`egress_rules` list to restrict it, or `[]` for no egress at all.

## Do not mix in `aws_security_group_rule`

This module writes its rules as **inline** `ingress`/`egress` blocks. Terraform
treats inline blocks as the complete, authoritative rule set for the security
group, so attaching a separate `aws_security_group_rule` (or
`aws_vpc_security_group_ingress_rule`) resource to `module.security_group.id`
produces a permanent diff, and every apply deletes whichever side ran last.
Declare every rule through `ingress_rules`/`egress_rules` instead.

## Requirements

| Name      | Version  |
|-----------|----------|
| terraform | >= 1.5   |
| aws       | >= 5.0   |

## Inputs

| Name                           | Description                                                                          | Type                | Default             | Required |
|--------------------------------|--------------------------------------------------------------------------------------|---------------------|---------------------|:--------:|
| `name`                         | Name of the security group.                                                          | `string`            | n/a                 |   yes    |
| `description`                  | Description of the security group.                                                   | `string`            | `"Managed by Terraform"` |  no  |
| `vpc_id`                       | ID of the VPC in which to create the security group.                                 | `string`            | n/a                 |   yes    |
| `ingress_rules`                | List of ingress rules to apply. Each rule needs at least one entry across `cidr_blocks`/`ipv6_cidr_blocks`. | `list(object(...))` | `[]`                |    no    |
| `egress_rules`                 | List of egress rules to apply.                                                       | `list(object(...))` | allow-all outbound  |    no    |
| `guarded_ingress_ports`        | Ports that may not be opened to a `/0` CIDR without an opt-in. `[]` disables the guard. | `list(number)`   | see above           |    no    |
| `allow_public_guarded_ingress` | Accept exposure of a guarded port to an unrestricted CIDR.                           | `bool`              | `false`             |    no    |
| `tags`                         | Tags applied to the security group.                                                  | `map(string)`       | `{}`                |    no    |

## Outputs

| Name     | Description                                    |
|----------|------------------------------------------------|
| `id`     | ID of the security group.                      |
| `arn`    | ARN of the security group.                     |
| `name`   | Name of the security group.                    |
| `vpc_id` | ID of the VPC the security group belongs to.   |

## Tests

`tests/` holds a [`terraform test`](https://developer.hashicorp.com/terraform/language/tests)
suite that runs against a mocked AWS provider — no credentials, no network:

```sh
terraform init -backend=false
terraform test
```

Running the suite needs Terraform (or OpenTofu) >= 1.7 for `mock_provider`. The
module itself still only requires >= 1.5.

## License

[MIT](LICENSE)
