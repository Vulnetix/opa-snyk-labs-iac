# Intent: IAM account password policy must enforce a minimum length.
# Reference: Snyk Labs NEW_PASSWORD_POLICY rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.snyk_password_policy

import rego.v1

import data.vulnetix.snyk_labs.helpers

metadata := {
	"id": "SNYK-LABS-IAM-PWD-001",
	"name": "IAM account password policy minimum length",
	"description": "`aws_iam_account_password_policy` should declare `minimum_password_length >= 17` (stricter than the CIS recommendation of 14).",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [521],
	"capec": ["CAPEC-16"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam", "password-policy"],
}

_minimum_length := 17

findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "aws_iam_account_password_policy")
	length_match := regex.find_n(`minimum_password_length\s*=\s*([0-9]+)`, block, 1)
	count(length_match) > 0
	length_str := regex.replace(length_match[0], `\D`, "")
	to_number(length_str) < _minimum_length
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("minimum_password_length is %s; must be at least %d.", [length_str, _minimum_length]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(content, offset),
		"snippet": length_match[0],
	}
}

# Missing minimum_password_length entirely
findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "aws_iam_account_password_policy")
	not regex.match(`minimum_password_length\s*=`, block)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_iam_account_password_policy declares no minimum_password_length (must be >= %d).", [_minimum_length]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(content, offset),
		"snippet": "aws_iam_account_password_policy",
	}
}
