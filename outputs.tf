output "id" {
  description = "ID of the security group."
  value       = aws_security_group.this.id
}

output "arn" {
  description = "ARN of the security group."
  value       = aws_security_group.this.arn
}

output "name" {
  description = "Name of the security group."
  value       = aws_security_group.this.name
}

output "vpc_id" {
  description = "ID of the VPC the security group belongs to."
  value       = aws_security_group.this.vpc_id
}
