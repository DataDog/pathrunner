package payloads

// Standard payload tags for filtering and discovery

// Service tags indicate which AWS service context the payload is designed for
const (
	TagServiceLambda    = "lambda"
	TagServiceEC2       = "ec2"
	TagServiceECS       = "ecs"
	TagServiceAppRunner = "apprunner"
	TagServiceCodeBuild = "codebuild"
	TagServiceGlue      = "glue"
	TagServiceSageMaker = "sagemaker"
)

// Language tags indicate the programming/scripting language of the payload
const (
	TagLanguagePython     = "python"
	TagLanguageNodeJS     = "nodejs"
	TagLanguageBash       = "bash"
	TagLanguagePowerShell = "powershell"
	TagLanguageGo         = "go"
)

// Technique tags categorize the exploitation technique
const (
	TagTechniqueExfil        = "exfil"         // Credential/data exfiltration
	TagTechniqueBackdoor     = "backdoor"      // Persistence mechanism
	TagTechniqueReverseShell = "reverse_shell" // Interactive shell
	TagTechniqueDirectAction = "direct_action" // Immediate privilege escalation
	TagTechniqueRecon        = "recon"         // Reconnaissance/enumeration
)

// Transport tags indicate how data/commands are transmitted
const (
	TagTransportWebhook    = "webhook"    // HTTP/HTTPS webhook
	TagTransportOutput     = "output"     // Function/command output
	TagTransportNetwork    = "network"    // Direct network connection
	TagTransportFilesystem = "filesystem" // File-based exfil
	TagTransportDNS        = "dns"        // DNS-based exfil
)

// TagFilter helps filter payloads based on tag requirements
type TagFilter struct {
	// RequireAll tags must all be present
	RequireAll []string
	// RequireAny tags - at least one must be present
	RequireAny []string
	// Exclude tags - none of these can be present
	Exclude []string
}

// Matches checks if a payload's tags match the filter
func (f *TagFilter) Matches(payloadTags []string) bool {
	tagSet := make(map[string]bool)
	for _, tag := range payloadTags {
		tagSet[tag] = true
	}

	// Check exclusions first
	for _, excludeTag := range f.Exclude {
		if tagSet[excludeTag] {
			return false
		}
	}

	// Check required tags
	for _, requiredTag := range f.RequireAll {
		if !tagSet[requiredTag] {
			return false
		}
	}

	// Check any tags
	if len(f.RequireAny) > 0 {
		foundAny := false
		for _, anyTag := range f.RequireAny {
			if tagSet[anyTag] {
				foundAny = true
				break
			}
		}
		if !foundAny {
			return false
		}
	}

	return true
}

// HasTag checks if a payload has a specific tag
func HasTag(payloadTags []string, tag string) bool {
	for _, t := range payloadTags {
		if t == tag {
			return true
		}
	}
	return false
}

// HasAnyTag checks if a payload has any of the specified tags
func HasAnyTag(payloadTags []string, tags []string) bool {
	for _, tag := range tags {
		if HasTag(payloadTags, tag) {
			return true
		}
	}
	return false
}

// HasAllTags checks if a payload has all of the specified tags
func HasAllTags(payloadTags []string, tags []string) bool {
	for _, tag := range tags {
		if !HasTag(payloadTags, tag) {
			return false
		}
	}
	return true
}
