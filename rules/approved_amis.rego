# Intent: EC2 instances must use an AMI from an approved allowlist.
# Reference: Snyk Labs APPROVED_AMIS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.snyk_approved_amis

import rego.v1

import data.vulnetix.snyk_labs.helpers

metadata := {
	"id": "SNYK-LABS-AMI-001",
	"name": "EC2 instance is using an unapproved AMI",
	"description": "Each `aws_instance` AMI must be in an allowlist. Fork and tailor the `_approved_amis` set for your environment.",
	"help_uri": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1357],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ec2", "ami", "terraform"],
}

_approved_amis := {
	"ami-00c39f71452c08778",
	"ami-02f97949d306b597a",
	"ami-04581fbf744a7d11f",
	"ami-0533def491c57d991",
}

findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "aws_instance")
	ami_match := regex.find_n(`ami\s*=\s*"([^"]+)"`, block, 1)
	count(ami_match) > 0
	ami := trim(regex.replace(ami_match[0], `ami\s*=\s*"|"`, ""), `"`)
	not _approved_amis[ami]
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_instance uses unapproved AMI %q.", [ami]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(content, offset),
		"snippet": ami_match[0],
	}
}
