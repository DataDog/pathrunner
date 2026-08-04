// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

import (
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// InteractiveShellPayload opens a live shell through the SSM session, bridging
// the operator's terminal directly to the instance. No reverse connection needed —
// ssm:StartSession already provides the command channel.
type InteractiveShellPayload struct{}

func init() {
	_ = payloads.Register(&InteractiveShellPayload{})
}

func (p *InteractiveShellPayload) GetName() string { return "shell/interactive" }

func (p *InteractiveShellPayload) GetDescription() string {
	return "Open a live interactive shell via the SSM session (no reverse connection required)"
}

func (p *InteractiveShellPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
		payloads.TagLanguageBash,
		payloads.TagTechniqueAccess,
	}
}

func (p *InteractiveShellPayload) GetOptions() []modules.Option { return nil }

func (p *InteractiveShellPayload) Validate(_ map[string]string) error { return nil }

// GenerateCode is unused — this payload is detected via InteractivePayload and
// the module hands the terminal directly to aws ssm start-session instead.
func (p *InteractiveShellPayload) GenerateCode(_ map[string]string) (string, error) {
	return "", nil
}

func (p *InteractiveShellPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// IsInteractive signals to the ssm_startsession module to bypass script
// execution and bridge stdin/stdout directly to the SSM session process.
func (p *InteractiveShellPayload) IsInteractive() bool { return true }
