# Intent: S3 buckets must declare owner and classification tags.
# Reference: Snyk Labs REQUIRED_S3_BUCKET_TAGS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.snyk_s3_required_tags

import rego.v1

import data.vulnetix.snyk_labs.helpers

metadata := {
	"id": "SNYK-LABS-S3-TAGS-001",
	"name": "S3 bucket must declare owner and classification tags",
	"description": "Each `aws_s3_bucket` must have `tags.owner` (from allowed team list) and `tags.classification` (public | internal | confidential).",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "tagging", "terraform"],
}

_allowed_owners := {"devteam1", "devteam2", "devteam3", "devteam4"}
_allowed_classifications := {"public", "internal", "confidential"}

findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "aws_s3_bucket")
	name := helpers.resource_name(block)
	not _has_valid_owner(block)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q missing or unknown `tags.owner` (must be one of %s).", [name, concat(",", [o | some o in _allowed_owners])]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(content, offset),
		"snippet": sprintf("aws_s3_bucket %q", [name]),
	}
}

findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "aws_s3_bucket")
	name := helpers.resource_name(block)
	not _has_valid_classification(block)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q missing or unknown `tags.classification` (public|internal|confidential).", [name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(content, offset),
		"snippet": sprintf("aws_s3_bucket %q", [name]),
	}
}

_has_valid_owner(block) if {
	owner_match := regex.find_n(`owner\s*=\s*"([^"]+)"`, block, 1)
	count(owner_match) > 0
	owner := regex.replace(owner_match[0], `.*"([^"]+)".*`, "$1")
	_allowed_owners[owner]
}

_has_valid_classification(block) if {
	cls_match := regex.find_n(`classification\s*=\s*"([^"]+)"`, block, 1)
	count(cls_match) > 0
	cls := regex.replace(cls_match[0], `.*"([^"]+)".*`, "$1")
	_allowed_classifications[cls]
}
