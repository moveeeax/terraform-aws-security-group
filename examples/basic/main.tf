terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "region" {
  description = "AWS region to deploy the example security group into."
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID to attach the example security group to."
  type        = string
}

provider "aws" {
  region = var.region
}

module "security_group" {
  source = "../.."

  name        = "example-web-sg"
  description = "Allow inbound HTTP and HTTPS"
  vpc_id      = var.vpc_id

  ingress_rules = [
    {
      description = "HTTP"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "HTTPS"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]

  tags = {
    Environment = "sandbox"
    ManagedBy   = "terraform"
  }
}

output "security_group_id" {
  value = module.security_group.id
}
