# Terraform configuration with intentional security issues for testing checkov
# WARNING: Do NOT use this configuration in production - it contains security vulnerabilities
#
# This file intentionally includes:
# - Hardcoded credentials (passwords, API keys)
# - Placeholder resource IDs (AMIs, subnet IDs)
# - Insecure configurations across various AWS services
#
# All issues in this file are INTENTIONAL for checkov testing purposes.

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# CKV_AWS_18: S3 bucket without access logging
# CKV_AWS_19: S3 bucket without server-side encryption
# CKV_AWS_21: S3 bucket without versioning
# CKV_AWS_145: S3 bucket without KMS encryption
# CKV2_AWS_6: S3 bucket without public access block
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket-example"

  tags = {
    Name        = "Insecure Bucket"
    Environment = "test"
  }
}

# CKV_AWS_20: S3 bucket with public ACL
resource "aws_s3_bucket_acl" "insecure_bucket_acl" {
  bucket = aws_s3_bucket.insecure_bucket.id
  acl    = "public-read"
}

# CKV_AWS_23: Security group with unrestricted ingress on all ports
# CKV_AWS_24: Security group allows ingress from 0.0.0.0/0 to SSH port
# CKV_AWS_25: Security group allows ingress from 0.0.0.0/0 to RDP port
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "Security group with overly permissive rules"

  # Allows SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere - insecure"
  }

  # Allows RDP from anywhere
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP from anywhere - insecure"
  }

  # Allows all traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All TCP from anywhere - insecure"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "wide-open-security-group"
  }
}

# CKV_AWS_79: EC2 instance without IMDSv2
# CKV_AWS_8: EC2 instance with unencrypted EBS volume
# CKV_AWS_126: EC2 instance without detailed monitoring
resource "aws_instance" "insecure_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Unencrypted root volume
  root_block_device {
    volume_type = "gp2"
    volume_size = 20
    encrypted   = false
  }

  # Public IP enabled
  associate_public_ip_address = true

  # IMDSv2 not enforced (missing metadata_options block)

  tags = {
    Name = "insecure-instance"
  }
}

# CKV_AWS_16: RDS instance without encryption
# CKV_AWS_17: RDS instance publicly accessible
# CKV_AWS_118: RDS instance without enhanced monitoring
# CKV_AWS_157: RDS instance without IAM authentication
# CKV_AWS_161: RDS instance without auto minor version upgrade
resource "aws_db_instance" "insecure_rds" {
  identifier        = "insecure-database"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  db_name           = "mydb"
  username          = "admin"
  password          = "insecure_password_123"

  # No encryption
  storage_encrypted = false

  # Publicly accessible
  publicly_accessible = true

  # No deletion protection
  deletion_protection = false

  # No auto minor version upgrade
  auto_minor_version_upgrade = false

  # Skip final snapshot for testing
  skip_final_snapshot = true

  tags = {
    Name = "insecure-rds"
  }
}

# CKV_AWS_50: IAM policy with wildcard actions
# CKV_AWS_1: IAM policy allows * resource
resource "aws_iam_policy" "overly_permissive" {
  name        = "overly-permissive-policy"
  description = "An IAM policy with overly permissive permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# CKV_AWS_35: CloudTrail without encryption
# CKV_AWS_36: CloudTrail without log file validation
# CKV_AWS_67: CloudTrail not enabled for all regions
resource "aws_cloudtrail" "insecure_trail" {
  name           = "insecure-trail"
  s3_bucket_name = aws_s3_bucket.insecure_bucket.id

  # Multi-region disabled
  is_multi_region_trail = false

  # Log file validation disabled
  enable_log_file_validation = false

  # No KMS encryption (kms_key_id not set)

  tags = {
    Name = "insecure-cloudtrail"
  }
}

# CKV_AWS_37: EBS volume not encrypted
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false

  tags = {
    Name = "unencrypted-ebs"
  }
}

# CKV_AWS_5: Elasticsearch domain without encryption at rest
# CKV_AWS_84: Elasticsearch domain without node-to-node encryption
# CKV_AWS_137: Elasticsearch domain without HTTPS enforcement
resource "aws_elasticsearch_domain" "insecure_es" {
  domain_name           = "insecure-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # No encryption at rest
  encrypt_at_rest {
    enabled = false
  }

  # No node-to-node encryption
  node_to_node_encryption {
    enabled = false
  }

  # HTTPS not enforced
  domain_endpoint_options {
    enforce_https = false
  }

  tags = {
    Name = "insecure-elasticsearch"
  }
}

# CKV_AWS_41: Lambda function without X-Ray tracing
# CKV_AWS_115: Lambda function without reserved concurrent executions
# CKV_AWS_116: Lambda function without DLQ
resource "aws_lambda_function" "insecure_lambda" {
  filename         = "lambda.zip"
  function_name    = "insecure-lambda"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  source_code_hash = "placeholder"

  # No X-Ray tracing
  # No reserved concurrent executions
  # No DLQ configured

  environment {
    variables = {
      # Hardcoded secret - CKV_AWS_45
      API_KEY = "super_secret_api_key_12345"
    }
  }

  tags = {
    Name = "insecure-lambda"
  }
}

# IAM role for Lambda (required dependency)
resource "aws_iam_role" "lambda_role" {
  name = "insecure-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# CKV_AWS_26: SNS topic without encryption
resource "aws_sns_topic" "unencrypted" {
  name = "unencrypted-topic"

  # No KMS encryption (kms_master_key_id not set)

  tags = {
    Name = "unencrypted-sns"
  }
}

# CKV_AWS_27: SQS queue without encryption
resource "aws_sqs_queue" "unencrypted" {
  name = "unencrypted-queue"

  # No KMS encryption (kms_master_key_id not set)

  tags = {
    Name = "unencrypted-sqs"
  }
}

# CKV_AWS_7: KMS key without rotation
resource "aws_kms_key" "no_rotation" {
  description         = "KMS key without automatic rotation"
  enable_key_rotation = false

  tags = {
    Name = "no-rotation-kms"
  }
}

# CKV_AWS_58: EKS cluster without secrets encryption
# CKV_AWS_39: EKS cluster without logging
resource "aws_eks_cluster" "insecure_eks" {
  name     = "insecure-eks-cluster"
  role_arn = aws_iam_role.eks_role.arn

  vpc_config {
    subnet_ids = ["subnet-12345678", "subnet-87654321"]

    # Public endpoint enabled
    endpoint_public_access = true

    # Private endpoint disabled
    endpoint_private_access = false
  }

  # No encryption config (secrets not encrypted)
  # No enabled cluster log types

  tags = {
    Name = "insecure-eks"
  }
}

# IAM role for EKS (required dependency)
resource "aws_iam_role" "eks_role" {
  name = "insecure-eks-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

# CKV_AWS_51: ECR repository without image scanning
# CKV_AWS_136: ECR repository without immutable tags
resource "aws_ecr_repository" "insecure_ecr" {
  name = "insecure-ecr-repo"

  # No image scanning
  image_scanning_configuration {
    scan_on_push = false
  }

  # Mutable image tags (default)
  image_tag_mutability = "MUTABLE"

  tags = {
    Name = "insecure-ecr"
  }
}

# CKV_AWS_28: DynamoDB table without encryption
# CKV_AWS_119: DynamoDB table without point-in-time recovery
resource "aws_dynamodb_table" "insecure_dynamodb" {
  name         = "insecure-dynamodb-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # No point-in-time recovery
  point_in_time_recovery {
    enabled = false
  }

  # No server-side encryption with CMK
  server_side_encryption {
    enabled = false
  }

  tags = {
    Name = "insecure-dynamodb"
  }
}

# CKV_AWS_86: CloudFront distribution without logging
# CKV_AWS_174: CloudFront distribution without WAF
resource "aws_cloudfront_distribution" "insecure_cf" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.insecure_bucket.bucket_regional_domain_name
    origin_id   = "S3Origin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3Origin"
    viewer_protocol_policy = "allow-all" # HTTP allowed - insecure

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1" # Old TLS version - insecure
  }

  # No logging configured
  # No WAF ACL attached

  tags = {
    Name = "insecure-cloudfront"
  }
}

# CKV_AWS_88: EC2 launch configuration with public IP
resource "aws_launch_configuration" "insecure_lc" {
  name_prefix     = "insecure-lc-"
  image_id        = "ami-0c55b159cbfafe1f0"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.wide_open.id]

  # Public IP enabled
  associate_public_ip_address = true

  # Unencrypted root volume
  root_block_device {
    volume_type = "gp2"
    volume_size = 20
    encrypted   = false
  }

  lifecycle {
    create_before_destroy = true
  }
}

# CKV_AWS_33: KMS key policy allows * principal
resource "aws_kms_key" "overly_permissive_kms" {
  description = "KMS key with overly permissive policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAll"
        Effect    = "Allow"
        Principal = "*"
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })

  tags = {
    Name = "overly-permissive-kms"
  }
}

# CKV_AWS_46: API Gateway without access logging
# CKV_AWS_76: API Gateway without X-Ray tracing
resource "aws_api_gateway_rest_api" "insecure_api" {
  name        = "insecure-api"
  description = "API Gateway without proper security configurations"

  endpoint_configuration {
    types = ["EDGE"]
  }

  tags = {
    Name = "insecure-api-gateway"
  }
}

resource "aws_api_gateway_stage" "insecure_stage" {
  deployment_id = aws_api_gateway_deployment.insecure_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.insecure_api.id
  stage_name    = "prod"

  # No access logging
  # No X-Ray tracing

  tags = {
    Name = "insecure-api-stage"
  }
}

resource "aws_api_gateway_deployment" "insecure_deployment" {
  rest_api_id = aws_api_gateway_rest_api.insecure_api.id

  lifecycle {
    create_before_destroy = true
  }
}

# CKV_AWS_53: Redshift cluster without encryption
# CKV_AWS_142: Redshift cluster without logging
resource "aws_redshift_cluster" "insecure_redshift" {
  cluster_identifier = "insecure-redshift-cluster"
  database_name      = "mydb"
  master_username    = "admin"
  master_password    = "InsecurePass123!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  # Not encrypted
  encrypted = false

  # Publicly accessible
  publicly_accessible = true

  # Skip final snapshot
  skip_final_snapshot = true

  # No logging (logging block not configured)

  tags = {
    Name = "insecure-redshift"
  }
}

# CKV2_AWS_5: ALB without WAF
# CKV_AWS_91: ALB without access logging
# CKV_AWS_131: ALB not dropping invalid HTTP headers
resource "aws_lb" "insecure_alb" {
  name               = "insecure-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.wide_open.id]
  subnets            = ["subnet-12345678", "subnet-87654321"]

  # Not dropping invalid headers
  drop_invalid_header_fields = false

  # No access logging

  tags = {
    Name = "insecure-alb"
  }
}
