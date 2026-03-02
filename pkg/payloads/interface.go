package payloads

import "pathrunner/pkg/modules"

// Payload represents a reusable exploitation payload that can be used across multiple modules
type Payload interface {
	// GetName returns the unique identifier for this payload (e.g., "exfil/output", "exfil/webhook")
	GetName() string

	// GetDescription returns a human-readable description of what this payload does
	GetDescription() string

	// GetTags returns tags for filtering/discovery
	// Tags include: service (lambda, ec2), language (python, bash), technique (exfil, backdoor), transport (webhook, output)
	GetTags() []string

	// GetOptions returns payload-specific configuration options
	GetOptions() []modules.Option

	// GenerateCode generates the actual payload code based on provided options
	// For Lambda: returns Python/Node.js code
	// For EC2: returns bash script
	// For other services: returns appropriate format
	GenerateCode(options map[string]string) (string, error)

	// ProcessResult processes the raw result from payload execution
	// Can extract credentials, format output, etc.
	ProcessResult(result string) (string, error)

	// Validate checks if the provided options are valid for this payload
	Validate(options map[string]string) error
}

// PayloadInfo provides metadata about a payload for display purposes
type PayloadInfo struct {
	Name        string
	Description string
	Tags        []string
	Options     []modules.Option
}
