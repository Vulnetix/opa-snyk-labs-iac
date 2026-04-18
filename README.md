# opa-snyk-labs-iac

Vulnetix CLI-compatible OPA custom rules for Infrastructure-as-Code security checks, inspired by the [Snyk Labs IaC-to-Cloud example custom rules](https://github.com/snyk-labs/iac-to-cloud-example-custom-rules).

## Clean-room development

These rules were produced using a **clean-room approach**. The original Snyk Labs rules were consulted only to understand the *intent* of each security check. All Rego implementations were then written independently from scratch, targeting the Vulnetix CLI's text-scanning input model (`input.file_contents`) rather than Snyk's `snyk.resources()` / `snyk.relates()` APIs.

Key differences from the upstream Snyk Labs implementations:

- **Input model**: Vulnetix provides raw file contents as `input.file_contents` (a map of file path to file text). Rules scan this text directly using regex and string operations.
- **Resource parsing**: Terraform HCL blocks are parsed via regex-based matching (`helpers.resource_blocks`), not through a structured resource graph.
- **Cross-resource joins**: Related resources (e.g. `aws_vpc` + `aws_flow_log`) are linked by matching resource name references across files, replacing Snyk's `snyk.relates()` join API.

## Rules

| ID | Name | Severity | Kind |
|----|------|----------|------|
| SNYK-LABS-AMI-001 | EC2 instance is using an unapproved AMI | high | iac |
| SNYK-LABS-GH-001 | GitHub default branch deletion protection | high | iac |
| SNYK-LABS-IAM-PWD-001 | IAM account password policy minimum length | high | iac |
| SNYK-LABS-S3-TAGS-001 | S3 bucket must declare owner and classification tags | medium | iac |
| SNYK-LABS-S3-ACL-001 | S3 bucket ACL must be private | critical | iac |
| SNYK-LABS-VPC-001 | VPC must have flow logs unless tagged for exception | high | iac |

## Structure

```
opa-snyk-labs-iac/
├── rules/
│   ├── helpers.rego                                    # shared helper functions
│   ├── approved_amis.rego
│   ├── github_default_branch_deletion_protection.rego
│   ├── new_password_policy.rego
│   ├── required_s3_bucket_tags.rego
│   ├── s3_bucket_acl.rego
│   └── vpc_flow_log_exception.rego
├── LICENSE
└── README.md
```

All `.rego` files live under `rules/` so the Vulnetix CLI can discover and load them automatically.

## Usage

```bash
# Use alongside built-in rules
vulnetix scan --rule Vulnetix/opa-snyk-labs-iac

# Use only these custom rules (no built-ins)
vulnetix scan --rule Vulnetix/opa-snyk-labs-iac --disable-default-rules
```

## License

Apache License 2.0. Original rule intent from [snyk-labs/iac-to-cloud-example-custom-rules](https://github.com/snyk-labs/iac-to-cloud-example-custom-rules) (also Apache 2.0).
