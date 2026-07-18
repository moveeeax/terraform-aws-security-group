# terraform-aws-security-group

Terraform module that manages an [Amazon VPC](https://aws.amazon.com/vpc/)
security group. It creates a single security group and renders ingress and
egress rules from list-of-object variables, so callers can declare their rule
set inline without touching the resource.

## Usage

```hcl
module "security_group" {
  source = "github.com/cybercapybara/terraform-aws-security-group"

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

## Requirements

| Name      | Version  |
|-----------|----------|
| terraform | >= 1.5   |
| aws       | >= 5.0   |

## Inputs

| Name            | Description                                             | Type                | Default             | Required |
|-----------------|---------------------------------------------------------|---------------------|---------------------|:--------:|
| `name`          | Name of the security group.                             | `string`            | n/a                 |   yes    |
| `description`   | Description of the security group.                      | `string`            | `"Managed by Terraform"` |  no  |
| `vpc_id`        | ID of the VPC in which to create the security group.    | `string`            | n/a                 |   yes    |
| `ingress_rules` | List of ingress rules to apply.                         | `list(object(...))` | `[]`                |    no    |
| `egress_rules`  | List of egress rules to apply.                          | `list(object(...))` | allow-all outbound  |    no    |
| `tags`          | Tags applied to the security group.                     | `map(string)`       | `{}`                |    no    |

## Outputs

| Name     | Description                                    |
|----------|------------------------------------------------|
| `id`     | ID of the security group.                      |
| `arn`    | ARN of the security group.                     |
| `name`   | Name of the security group.                    |
| `vpc_id` | ID of the VPC the security group belongs to.   |

## License

[MIT](LICENSE)
