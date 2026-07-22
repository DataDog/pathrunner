// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package utils

import (
	"archive/zip"
	"bytes"
)

func CreateLambdaZip(pythonCode string) ([]byte, error) {
	return CreateLambdaZipWithFilename(pythonCode, "lambda_function.py")
}

// CreateLambdaZipWithFilename creates a Lambda deployment zip with a custom filename.
// This is needed when updating existing functions whose handler references a different
// module name (e.g., "index.handler" requires "index.py" not "lambda_function.py").
func CreateLambdaZipWithFilename(pythonCode string, filename string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	file, err := zipWriter.Create(filename)
	if err != nil {
		return nil, err
	}

	_, err = file.Write([]byte(pythonCode))
	if err != nil {
		return nil, err
	}

	err = zipWriter.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}