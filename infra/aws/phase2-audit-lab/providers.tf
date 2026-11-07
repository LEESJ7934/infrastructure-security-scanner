provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = local.tags
  }
}
locals {
  tags = {
    Project     = var.lab_name
    Environment = "isolated-lab"
    Owner       = var.owner
    Purpose     = "phase2-security-audit"
    ManagedBy   = "terraform-phase2-audit-lab"
  }
  sg_ports   = toset(["21", "23", "3389"])
  deny_ports = { "22" = 50, "23" = 51, "3389" = 52 }
}
