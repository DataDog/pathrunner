package modules

// BaseModule provides default implementations for Module interface methods.
// Embed this in concrete modules to reduce boilerplate — modules only need
// to implement Options() and Execute() (plus payload methods if applicable).
type BaseModule struct {
	Info PathInfo
}

// PathInfo returns the module's structured metadata.
func (b *BaseModule) PathInfo() PathInfo {
	return b.Info
}

// Name returns the path ID (e.g., "lambda-001").
func (b *BaseModule) Name() string {
	return b.Info.ID
}

// Description returns the human-readable description.
func (b *BaseModule) Description() string {
	return b.Info.Description
}

// PayloadOptions returns an empty slice by default.
// Override in modules that support payloads.
func (b *BaseModule) PayloadOptions(payload string) []Option {
	return []Option{}
}

// ListPayloads returns an empty slice by default.
// Override in modules that support payloads.
func (b *BaseModule) ListPayloads() []PayloadInfo {
	return []PayloadInfo{}
}
