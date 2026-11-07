output "audit_lab" {
  description = "Only Terraform-created LAB identities; export to private JSON after approved apply."
  value = {
    schema_version = 1
    account_id     = var.expected_account_id
    region         = var.region
    lab_name       = var.lab_name
    owner          = var.owner
    phase          = var.phase
    tags           = local.tags
    vpc_id         = aws_vpc.lab.id
    subnet_id      = aws_subnet.internal.id
    sg_id          = aws_security_group.lab.id
    nacl_id        = aws_network_acl.lab.id
    route_table_id = aws_route_table.lab.id
    igw_id         = aws_internet_gateway.lab.id
    log_group_arn  = aws_cloudwatch_log_group.flow.arn
    flow_role_arn  = aws_iam_role.flow.arn
  }
}
