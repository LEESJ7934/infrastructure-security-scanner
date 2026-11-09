# Created in both phases: identity/scope stays stable; only Flow Logs toggles.
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/${var.lab_name}/vpc-flow"
  retention_in_days = 1
  tags              = { Name = "${var.lab_name}-flow" }
}
resource "aws_iam_role" "flow" {
  name = "${var.lab_name}-flow-delivery"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.expected_account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ec2:${var.region}:${var.expected_account_id}:vpc-flow-log/*" }
      }
    }]
  })
  tags = { Name = "${var.lab_name}-flow-delivery" }
}
resource "aws_iam_role_policy" "flow" {
  name = "${var.lab_name}-flow-write"
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
      }, {
      Effect   = "Allow"
      Action   = ["logs:DescribeLogGroups"]
      Resource = "*"
    }]
  })
}
resource "aws_flow_log" "lab" {
  count                    = var.phase == "after" ? 1 : 0
  depends_on               = [aws_iam_role_policy.flow]
  iam_role_arn             = aws_iam_role.flow.arn
  log_destination          = aws_cloudwatch_log_group.flow.arn
  log_destination_type     = "cloud-watch-logs"
  traffic_type             = "ALL"
  vpc_id                   = aws_vpc.lab.id
  max_aggregation_interval = 60
  tags                     = { Name = "${var.lab_name}-flow" }
}
