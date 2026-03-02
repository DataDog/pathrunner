package payloads

import (
	"fmt"
	"sort"
	"sync"
)

// Global registry instance
var globalRegistry = NewRegistry()

// Registry manages all available payloads
type Registry struct {
	mu       sync.RWMutex
	payloads map[string]Payload
}

// NewRegistry creates a new payload registry
func NewRegistry() *Registry {
	return &Registry{
		payloads: make(map[string]Payload),
	}
}

// Register adds a payload to the global registry
// This is typically called in init() functions of payload packages
func Register(payload Payload) error {
	return globalRegistry.RegisterPayload(payload)
}

// RegisterPayload adds a payload to this registry
func (r *Registry) RegisterPayload(payload Payload) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := payload.GetName()
	if name == "" {
		return fmt.Errorf("payload name cannot be empty")
	}

	if _, exists := r.payloads[name]; exists {
		return fmt.Errorf("payload '%s' is already registered", name)
	}

	r.payloads[name] = payload
	return nil
}

// GetPayload retrieves a payload by name from the global registry
func GetPayload(name string) (Payload, error) {
	return globalRegistry.GetPayloadByName(name)
}

// GetPayloadByName retrieves a payload by name
func (r *Registry) GetPayloadByName(name string) (Payload, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	payload, exists := r.payloads[name]
	if !exists {
		return nil, fmt.Errorf("payload '%s' not found", name)
	}

	return payload, nil
}

// GetPayloadsByTags returns all payloads that have ALL the specified tags
func GetPayloadsByTags(tags []string) []Payload {
	return globalRegistry.FindPayloadsByTags(tags)
}

// FindPayloadsByTags returns all payloads that have ALL the specified tags
func (r *Registry) FindPayloadsByTags(tags []string) []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matching []Payload
	for _, payload := range r.payloads {
		if HasAllTags(payload.GetTags(), tags) {
			matching = append(matching, payload)
		}
	}

	// Sort by name for consistent ordering
	sort.Slice(matching, func(i, j int) bool {
		return matching[i].GetName() < matching[j].GetName()
	})

	return matching
}

// GetPayloadsByContext returns all payloads for a specific service context (e.g., "lambda", "ec2")
func GetPayloadsByContext(context string) []Payload {
	return globalRegistry.FindPayloadsByContext(context)
}

// FindPayloadsByContext returns all payloads for a specific service context
func (r *Registry) FindPayloadsByContext(context string) []Payload {
	return r.FindPayloadsByTags([]string{context})
}

// GetPayloadsByFilter returns all payloads matching the filter
func GetPayloadsByFilter(filter *TagFilter) []Payload {
	return globalRegistry.FindPayloadsByFilter(filter)
}

// FindPayloadsByFilter returns all payloads matching the filter
func (r *Registry) FindPayloadsByFilter(filter *TagFilter) []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matching []Payload
	for _, payload := range r.payloads {
		if filter.Matches(payload.GetTags()) {
			matching = append(matching, payload)
		}
	}

	// Sort by name for consistent ordering
	sort.Slice(matching, func(i, j int) bool {
		return matching[i].GetName() < matching[j].GetName()
	})

	return matching
}

// ListAllPayloads returns all registered payloads
func ListAllPayloads() []Payload {
	return globalRegistry.GetAllPayloads()
}

// GetAllPayloads returns all registered payloads
func (r *Registry) GetAllPayloads() []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	payloads := make([]Payload, 0, len(r.payloads))
	for _, payload := range r.payloads {
		payloads = append(payloads, payload)
	}

	// Sort by name for consistent ordering
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].GetName() < payloads[j].GetName()
	})

	return payloads
}

// GetPayloadInfo returns metadata about a payload for display
func GetPayloadInfo(name string) (*PayloadInfo, error) {
	payload, err := GetPayload(name)
	if err != nil {
		return nil, err
	}

	return &PayloadInfo{
		Name:        payload.GetName(),
		Description: payload.GetDescription(),
		Tags:        payload.GetTags(),
		Options:     payload.GetOptions(),
	}, nil
}

// Count returns the number of registered payloads
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.payloads)
}

// Clear removes all payloads from the registry (useful for testing)
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.payloads = make(map[string]Payload)
}
