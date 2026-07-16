package payloads

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// Payload represents a reusable exploitation payload that can be used across multiple modules
type Payload interface {
	// GetName returns the unique identifier for this payload (e.g., "exfil/response", "exfil/https")
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

// Verifiable is an optional interface for payloads whose effect can be checked programmatically.
// Event-triggered modules (ESM, CloudWatch Events, etc.) use this to confirm the payload executed
// successfully, since there is no direct invocation response to inspect.
type Verifiable interface {
	// VerifySuccess checks whether the payload's action has taken effect.
	// The config should belong to the identity that benefits from the payload's action.
	// Returns true if the effect is confirmed, false if not yet detected.
	VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error)
}

// SideEffectReporter is an optional interface for payloads that modify existing AWS resources.
// When a payload attaches a policy, modifies a role, etc., it reports those modifications so
// the module can track them for cleanup/reversal via workspace cleanup.
type SideEffectReporter interface {
	// ReportSideEffects returns resources that the payload modifies or creates as side effects.
	// The module sets ModuleID on each returned resource before tracking.
	// Called after successful execution (or verification for event-triggered modules).
	ReportSideEffects(options map[string]string) []modules.CreatedResource
}

// PayloadInfo provides metadata about a payload for display purposes
type PayloadInfo struct {
	Name        string
	Description string
	Tags        []string
	Options     []modules.Option
}
