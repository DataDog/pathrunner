package utils

import (
	"archive/zip"
	"bytes"
)

func CreateLambdaZip(pythonCode string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	file, err := zipWriter.Create("lambda_function.py")
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