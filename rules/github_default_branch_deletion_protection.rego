# Intent: GitHub default branch must be protected from deletion.
# Reference: Snyk Labs GITHUB_DEFAULT_BRANCH_DELETION_PROTECTION rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.snyk_github_branch_protection

import rego.v1

import data.vulnetix.snyk_labs.helpers

metadata := {
	"id": "SNYK-LABS-GH-001",
	"name": "GitHub default branch deletion protection",
	"description": "Each `github_repository` should have a companion `github_branch_protection` with `allows_deletions = false`.",
	"help_uri": "https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["github", "branch-protection", "terraform"],
}

findings contains finding if {
	some path, content in input.file_contents
	helpers.is_tf(path)
	some block in helpers.resource_blocks(content, "github_repository")
	repo_name := helpers.resource_name(block)
	not _has_protection(repo_name)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("github_repository %q has no github_branch_protection blocking deletions.", [repo_name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(content, offset),
		"snippet": sprintf("resource \"github_repository\" %q", [repo_name]),
	}
}

_has_protection(repo_name) if {
	some _, content in input.file_contents
	blocks := helpers.resource_blocks(content, "github_branch_protection")
	some block in blocks
	regex.match(sprintf(`github_repository\.%s\.`, [regex.split(`\.`, repo_name)[0]]), block)
	regex.match(`allows_deletions\s*=\s*false`, block)
}
