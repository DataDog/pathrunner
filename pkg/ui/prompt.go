// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ui

import (
	"fmt"

	"github.com/charmbracelet/huh"
)

// Select presents an interactive selection prompt and returns the selected index.
func Select(message string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, fmt.Errorf("no options provided")
	}

	huhOptions := make([]huh.Option[int], len(options))
	for i, opt := range options {
		huhOptions[i] = huh.NewOption(opt, i)
	}

	var selected int
	err := huh.NewSelect[int]().
		Title(message).
		Options(huhOptions...).
		Value(&selected).
		Run()

	if err != nil {
		return -1, err
	}

	return selected, nil
}

// MultiSelect presents an interactive multi-select prompt and returns selected indices.
func MultiSelect(message string, options []string) ([]int, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no options provided")
	}

	huhOptions := make([]huh.Option[int], len(options))
	for i, opt := range options {
		huhOptions[i] = huh.NewOption(opt, i)
	}

	var selected []int
	err := huh.NewMultiSelect[int]().
		Title(message).
		Options(huhOptions...).
		Value(&selected).
		Run()

	if err != nil {
		return nil, err
	}

	return selected, nil
}

// Input presents a text input prompt and returns the entered value.
func Input(message string) (string, error) {
	var value string
	err := huh.NewInput().
		Title(message).
		Value(&value).
		Run()

	if err != nil {
		return "", err
	}

	return value, nil
}

// Confirm presents a yes/no confirmation prompt.
func Confirm(message string) (bool, error) {
	var confirmed bool
	err := huh.NewConfirm().
		Title(message).
		Value(&confirmed).
		Run()

	if err != nil {
		return false, err
	}

	return confirmed, nil
}
