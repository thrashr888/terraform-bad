# CLAUDE.md

## 1. Project overview
- Purpose: intentionally insecure Terraform root module used to exercise Checkov and other security scanners.
- Scope: single AWS provider configuration in `main.tf` touching many services (S3, EC2, RDS, IAM, CloudTrail, EBS, OpenSearch/Elasticsearch, Lambda, SNS/SQS, KMS, EKS, ECR, DynamoDB, CloudFront, API Gateway, Redshift, ALB, etc.).
- Intentional vulnerabilities: every resource advertises its Checkov rule IDs (`CKV_*`) and dials features to their least secure settings (public ACLs, no encryption, permissive IAM policies, hard-coded secrets, etc.). Do **not** apply this configuration to any real AWS environment.
- Repository footprint: no modules or scripts beyond `main.tf`. Use this as a fixture for tooling, not as a deployable stack.

## 2. Key commands (build/test workflow)
All commands run from repo root.

| Goal | Command | Notes |
| --- | --- | --- |
| Format files | `terraform fmt` | Keeps `main.tf` canonical before committing changes. |
| Init provider/plugins | `terraform init` | Needed once per environment before validation or planning. |
| Static validation | `terraform validate` | Ensures syntactic correctness without checking security posture. |
| Security scanning | `checkov -d .` | Primary reason this repo exists; scan should report numerous failures. |
| Plan (dry run) | `terraform plan` | Only if you need to check graph consistency; never run `apply` against production. |
| Destroy (cleanup) | `terraform destroy` | Use only in a disposable sandbox if you accidentally created resources. |

> **Safety**: Avoid `terraform apply` unless you are inside an isolated test account you are willing to fully clean up. Many resources use placeholder IDs and will fail to provision anyway.

## 3. Architecture patterns
- **Single root module**: Everything lives in `main.tf`; no submodules, Terragrunt, or workspaces. Keep additions in this file unless you are restructuring the repo on purpose.
- **Service coverage over correctness**: The config favors breadth—touching many AWS services—to maximize scanner surface. Resources typically omit dependencies (e.g., referencing placeholder subnets) and expect to fail on apply; correctness is secondary to demonstrating misconfigurations.
- **Inline documentation**: Comments enumerate Checkov rule IDs for each anti-pattern. When introducing new insecure examples, continue listing the relevant `CKV*` identifiers to help scanner authors.
- **Default provider config**: Single `aws` provider pinned to `~> 5.0` and region `us-east-1`. There is no backend or remote state configuration; Terraform will default to the local backend.

## 4. Coding conventions
- **HCL style**: Follow `terraform fmt`. Use two-space indentation, `snake_case` resource names prefixed with the service (e.g., `aws_s3_bucket.insecure_bucket`).
- **Tagging**: Existing resources add minimal `tags` (`Name`, `Environment`). Mirror this pattern for consistency, even when the resource is intentionally insecure.
- **Descriptive comments**: Each block lists the violated Checkov controls (`# CKV_AWS_XX`). Continue documenting new violations so downstream consumers know what to expect.
- **Hard-coded test values**: Credentials, IDs, and ARNs are deliberately fake or insecure. When extending the file, keep values obviously non-production (placeholders, `example`, `insecure` prefixes) to avoid leaking real secrets.
- **No modules/variables**: Stick to literal values inside resources. Introducing variables or modules is unnecessary unless expanding the repo for a new test scenario that explicitly requires them.
- **Safety first**: Never ship automation that runs `terraform apply` automatically. All scripts/docs should remind readers that this configuration is for scanners only.
