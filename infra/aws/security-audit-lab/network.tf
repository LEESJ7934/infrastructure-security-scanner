resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = false
  tags                 = { Name = "${var.lab_name}-vpc" }
}
resource "aws_subnet" "internal" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  map_public_ip_on_launch = var.phase == "before"
  tags                    = { Name = "${var.lab_name}-internal-target" }
}
# Retained after remediation to avoid replacement/scope changes. No compute exists.
resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.lab_name}-igw" }
}
resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.lab_name}-routes" }
}
resource "aws_route_table_association" "internal" {
  subnet_id      = aws_subnet.internal.id
  route_table_id = aws_route_table.lab.id
}
resource "aws_route" "public" {
  count                  = var.phase == "before" ? 1 : 0
  route_table_id         = aws_route_table.lab.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.lab.id
}
