# Unattached SG: reproduces a setting, never a reachable management service.
resource "aws_security_group" "lab" {
  name        = "${var.lab_name}-unattached"
  description = "Isolated settings-only security audit LAB"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "${var.lab_name}-unattached" }
}
resource "aws_vpc_security_group_ingress_rule" "open" {
  for_each          = var.phase == "before" ? local.sg_ports : toset([])
  security_group_id = aws_security_group.lab.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
  tags              = { Name = "${var.lab_name}-before-${each.key}" }
}
resource "aws_network_acl" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.lab_name}-custom-acl" }
}
resource "aws_network_acl_association" "internal" {
  subnet_id      = aws_subnet.internal.id
  network_acl_id = aws_network_acl.lab.id
}
resource "aws_network_acl_rule" "allow_in" {
  network_acl_id = aws_network_acl.lab.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
resource "aws_network_acl_rule" "allow_out" {
  network_acl_id = aws_network_acl.lab.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
resource "aws_network_acl_rule" "deny" {
  for_each       = var.phase == "after" ? local.deny_ports : {}
  network_acl_id = aws_network_acl.lab.id
  rule_number    = each.value
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "198.51.100.10/32"
  from_port      = tonumber(each.key)
  to_port        = tonumber(each.key)
}
