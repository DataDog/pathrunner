// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package modules

import (
	"fmt"
	"sort"
	"strings"
)

var (
	registry      = make(map[string]func() Module)
	aliasMap      = make(map[string]string)   // alias -> primary ID
	pathInfoCache = make(map[string]PathInfo) // primary ID -> PathInfo

	// retiredIDs maps module IDs that no longer resolve to the module ID that
	// now implements the same technique. These IDs were published at some
	// point, so they must never be silently re-registered — LoadModule refuses
	// them with a pointer to their replacement instead of a generic
	// "unknown module" error.
	retiredIDs = map[string]string{
		// The PassRole + RequestSpotInstances module was ec2-004 until
		// pathfinding.cloud realigned its EC2 path IDs (2026-11-13) and the
		// technique moved to ec2-003. Retired IDs are never reused.
		"ec2-004": "ec2-003",
	}
)

// Register registers a module constructor under the given name.
// If the module provides PathInfo with Aliases, those are auto-registered.
func Register(name string, constructor func() Module) {
	// Retired IDs are permanent: re-registering one would silently point
	// every historical reference at the wrong module.
	if replacement, retired := retiredIDs[name]; retired {
		panic(fmt.Sprintf("refusing to register retired module ID %q (replaced by %q)", name, replacement))
	}

	registry[name] = constructor

	// Eagerly build PathInfo cache and register aliases
	mod := constructor()
	info := mod.PathInfo()
	if info.ID != "" {
		pathInfoCache[info.ID] = info
		for _, alias := range info.Aliases {
			aliasMap[alias] = info.ID
		}
	}
}

// GetModule loads a module by name or alias. Returns nil if not found.
// Convenience wrapper around LoadModule for callers that prefer a nil check over error handling.
func GetModule(modulePath string) Module {
	mod, err := LoadModule(modulePath)
	if err != nil {
		return nil
	}
	return mod
}

// RetiredModuleReplacement returns the module ID that replaced the given
// retired module ID. ok is false when moduleID is not a retired ID.
func RetiredModuleReplacement(moduleID string) (replacement string, ok bool) {
	replacement, ok = retiredIDs[moduleID]
	return replacement, ok
}

// LoadModule loads a module by name or alias. Returns the module or an error.
func LoadModule(modulePath string) (Module, error) {
	// Direct lookup
	if constructor, exists := registry[modulePath]; exists {
		return constructor(), nil
	}
	// Alias lookup
	if primary, exists := aliasMap[modulePath]; exists {
		if constructor, exists := registry[primary]; exists {
			return constructor(), nil
		}
	}
	// Retired IDs get a pointed message instead of a generic one.
	if replacement, ok := retiredIDs[modulePath]; ok {
		return nil, fmt.Errorf("module %q is retired: it was renamed to %q", modulePath, replacement)
	}
	return nil, fmt.Errorf("unknown module: %s", modulePath)
}

// ListModules returns all primary module names sorted alphabetically.
func ListModules() []string {
	var modules []string
	for name := range registry {
		modules = append(modules, name)
	}
	sort.Strings(modules)
	return modules
}

// GetModuleInfo returns the name and description for a module path.
func GetModuleInfo(modulePath string) (string, string, error) {
	constructor, exists := registry[modulePath]
	if !exists {
		return "", "", fmt.Errorf("unknown module: %s", modulePath)
	}

	module := constructor()
	return module.Name(), module.Description(), nil
}

// GetPathInfo returns the cached PathInfo for a module ID or alias.
func GetPathInfo(name string) (PathInfo, bool) {
	// Direct lookup in cache
	if info, exists := pathInfoCache[name]; exists {
		return info, true
	}
	// Alias lookup
	if primary, exists := aliasMap[name]; exists {
		if info, exists := pathInfoCache[primary]; exists {
			return info, true
		}
	}
	return PathInfo{}, false
}

// ListPathInfos returns all cached PathInfo entries sorted by ID.
func ListPathInfos() []PathInfo {
	var infos []PathInfo
	for _, info := range pathInfoCache {
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].ID < infos[j].ID
	})
	return infos
}

// SearchModules searches modules by keyword across ID, Name, Description,
// Category, Services, and Aliases. Returns matching PathInfo entries.
func SearchModules(query string) []PathInfo {
	query = strings.ToLower(query)
	var results []PathInfo

	for _, info := range pathInfoCache {
		if matchesQuery(info, query) {
			results = append(results, info)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}

// ListModulesByCategory returns modules matching the given category.
func ListModulesByCategory(category string) []PathInfo {
	category = strings.ToLower(category)
	var results []PathInfo

	for _, info := range pathInfoCache {
		if strings.ToLower(info.Category) == category {
			results = append(results, info)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}

// ListModulesByService returns modules that involve the given AWS service.
func ListModulesByService(service string) []PathInfo {
	service = strings.ToLower(service)
	var results []PathInfo

	for _, info := range pathInfoCache {
		for _, svc := range info.Services {
			if strings.ToLower(svc) == service {
				results = append(results, info)
				break
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results
}

// matchesQuery checks if a PathInfo matches a search query.
func matchesQuery(info PathInfo, query string) bool {
	// Check ID
	if strings.Contains(strings.ToLower(info.ID), query) {
		return true
	}
	// Check Name
	if strings.Contains(strings.ToLower(info.Name), query) {
		return true
	}
	// Check Description
	if strings.Contains(strings.ToLower(info.Description), query) {
		return true
	}
	// Check Category
	if strings.Contains(strings.ToLower(info.Category), query) {
		return true
	}
	// Check Services
	for _, svc := range info.Services {
		if strings.Contains(strings.ToLower(svc), query) {
			return true
		}
	}
	// Check Aliases
	for _, alias := range info.Aliases {
		if strings.Contains(strings.ToLower(alias), query) {
			return true
		}
	}
	// Check permissions
	for _, perm := range info.Permissions.Required {
		if strings.Contains(strings.ToLower(perm.Permission), query) {
			return true
		}
	}
	return false
}

// ResetRegistry clears all registered modules, aliases, and cached PathInfo.
// Used only in tests.
func ResetRegistry() {
	registry = make(map[string]func() Module)
	aliasMap = make(map[string]string)
	pathInfoCache = make(map[string]PathInfo)
}
