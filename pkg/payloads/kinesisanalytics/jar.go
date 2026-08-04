// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package kinesisanalytics

import _ "embed"

// embeddedJAR is the universal Pathrunner Flink payload JAR, embedded at build time.
// It dispatches to the appropriate payload handler based on the PAYLOAD_TYPE
// EnvironmentProperty, so one binary covers all payload types.
//
// To rebuild after changing jars/src/: run make build-jars (requires Docker).
//
//go:embed jars/payload.jar
var embeddedJAR []byte

// GetEmbeddedJAR returns the pre-compiled Flink payload JAR bytes.
func GetEmbeddedJAR() []byte { return embeddedJAR }
