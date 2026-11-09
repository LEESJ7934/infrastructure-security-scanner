variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "An explicit 12-digit expected account is required."
  }
}
variable "region" {
  type    = string
  default = "ap-northeast-2"
  validation {
    condition     = var.region == "ap-northeast-2"
    error_message = "Only ap-northeast-2 is permitted."
  }
}
variable "lab_name" {
  type = string
  validation {
    condition     = can(regex("^scanner-p2audit-[a-z0-9]{6,12}$", var.lab_name))
    error_message = "Use scanner-p2audit- plus a unique 6-12 character suffix."
  }
}
variable "owner" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,32}$", var.owner))
    error_message = "Use a non-secret owner alias (1-32 letters/digits/_/-)."
  }
}
variable "phase" {
  type    = string
  default = "before"
  validation {
    condition     = contains(["before", "after"], var.phase)
    error_message = "Phase must be before or after."
  }
}
variable "vpc_cidr" {
  type    = string
  default = "10.206.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && can(regex("^10\\.", var.vpc_cidr)) && try(tonumber(split("/", var.vpc_cidr)[1]) == 16, false)
    error_message = "Choose an operator-reviewed private 10.x.0.0/16 LAB CIDR."
  }
}
