package modules

import (
	"fmt"
	"sort"
)

var registry = make(map[string]func() Module)

func Register(name string, constructor func() Module) {
	registry[name] = constructor
}

func LoadModule(modulePath string) (Module, error) {
	if constructor, exists := registry[modulePath]; exists {
		return constructor(), nil
	}
	return nil, fmt.Errorf("unknown module: %s", modulePath)
}

func ListModules() []string {
	var modules []string
	for name := range registry {
		modules = append(modules, name)
	}
	sort.Strings(modules)
	return modules
}

func GetModuleInfo(modulePath string) (string, string, error) {
	constructor, exists := registry[modulePath]
	if !exists {
		return "", "", fmt.Errorf("unknown module: %s", modulePath)
	}

	module := constructor()
	return module.Name(), module.Description(), nil
}