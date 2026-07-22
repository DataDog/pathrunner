// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package core

import (
	"github.com/DataDog/pathrunner/pkg/modules"
)

func LoadModule(modulePath string) (modules.Module, error) {
	return modules.LoadModule(modulePath)
}