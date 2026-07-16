package core

import (
	"github.com/DataDog/pathrunner/pkg/modules"
)

func LoadModule(modulePath string) (modules.Module, error) {
	return modules.LoadModule(modulePath)
}