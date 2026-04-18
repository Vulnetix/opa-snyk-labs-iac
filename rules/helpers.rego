# Helper functions for Vulnetix IaC rules.
# Not a rule — no metadata/findings exported.

package vulnetix.snyk_labs.helpers

import rego.v1

is_tf(path) if endswith(lower(path), ".tf")

# Line number of a given byte offset in content.
line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

# Extract the declared resource name from a Terraform block header.
resource_name(block) := name if {
	parts := regex.find_n(`"[^"]+"\s+"([^"]+)"`, block, 1)
	count(parts) > 0
	captures := regex.find_n(`"([^"]+)"`, parts[0], -1)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

# Find all top-level resource blocks of a given type across a file's content.
# Returns a list of the block text (starting at `resource "type" "name" {` line).
resource_blocks(content, type) := blocks if {
	# Match `resource "<type>" "<name>" { ... }` using a greedy single-block regex.
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
}
