# Intent: S3 bucket ACL must be private.
# Reference: Snyk Labs S3_BUCKET_ACL rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.snyk_s3_bucket_acl

import rego.v1

import data.vulnetix.snyk_labs.helpers

metadata := {
	"id": "SNYK-LABS-S3-ACL-001",
	"name": "S3 bucket ACL must be private",
	"description": "Each `aws_s3_bucket_acl` must set `acl = \"private\"`.",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
	"languages": ["terraform"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [732],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "acl", "terraform"],
}

findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "aws_s3_bucket_acl")
	acl_match := regex.find_n(`acl\s*=\s*"([^"]+)"`, block, 1)
	count(acl_match) > 0
	acl := regex.replace(acl_match[0], `.*"([^"]+)".*`, "$1")
	acl != "private"
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl has acl=%q; must be \"private\".", [acl]),
		"artifact_uri": path,
		"severity": "critical",
		"level": "error",
		"start_line": helpers.line_of(content, offset),
		"snippet": acl_match[0],
	}
}
