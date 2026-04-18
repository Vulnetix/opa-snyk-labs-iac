# Intent: VPC flow logs required unless the VPC carries an exemption tag.
# Reference: Snyk Labs VPC_FLOW_LOG_EXCEPTION rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.snyk_vpc_flow_log

import rego.v1

import data.vulnetix.snyk_labs.helpers

metadata := {
	"id": "SNYK-LABS-VPC-001",
	"name": "VPC must have flow logs unless tagged for exception",
	"description": "Each `aws_vpc` must be paired with an `aws_flow_log`, unless it carries the exemption tag `name = \"cloudbank-fix\"`.",
	"help_uri": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [778],
	"capec": [],
	"attack_technique": ["T1562.008"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "vpc", "flow-logs", "terraform"],
}

findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "aws_vpc")
	vpc_name := helpers.resource_name(block)
	not _is_exempt(block)
	not _has_flow_log(vpc_name)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_vpc %q has no aws_flow_log and no `name=cloudbank-fix` tag exemption.", [vpc_name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(content, offset),
		"snippet": sprintf("aws_vpc %q", [vpc_name]),
	}
}

_is_exempt(block) if {
	regex.match(`(?s)tags\s*=\s*\{[^}]*\bname\s*=\s*"cloudbank-fix"`, block)
}

_has_flow_log(vpc_name) if {
	some _, content in input.file_contents
	blocks := helpers.resource_blocks(content, "aws_flow_log")
	some block in blocks
	regex.match(sprintf(`aws_vpc\.%s\.`, [regex.split(`\.`, vpc_name)[0]]), block)
}
