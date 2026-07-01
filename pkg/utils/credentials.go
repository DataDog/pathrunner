package utils

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

type ExtractedCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	Source          string
	// ProfileName is set when credentials were parsed from an AWS credentials file stanza.
	// Used as the suggested identity name instead of the generated one.
	ProfileName string
}

// tryEnvVarFormat attempts to parse AWS_* environment variable format
func tryEnvVarFormat(text string, creds *ExtractedCredentials) bool {
	accessKeyRegex := regexp.MustCompile(`AWS_ACCESS_KEY_ID=([A-Z0-9]+)`)
	secretKeyRegex := regexp.MustCompile(`AWS_SECRET_ACCESS_KEY=([A-Za-z0-9+/=]+)`)
	sessionTokenRegex := regexp.MustCompile(`AWS_SESSION_TOKEN=([A-Za-z0-9+/=]+)`)

	if matches := accessKeyRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.AccessKeyID = matches[1]
	}

	if matches := secretKeyRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.SecretAccessKey = matches[1]
	}

	if matches := sessionTokenRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.SessionToken = matches[1]
	}

	return creds.AccessKeyID != "" && creds.SecretAccessKey != ""
}

// tryJSONFormat attempts to parse JSON format with double quotes
func tryJSONFormat(text string, creds *ExtractedCredentials) bool {
	accessKeyJSONRegex := regexp.MustCompile(`"access_key_id":\s*"([A-Z0-9]+)"`)
	secretKeyJSONRegex := regexp.MustCompile(`"secret_access_key":\s*"([A-Za-z0-9+/=]+)"`)
	sessionTokenJSONRegex := regexp.MustCompile(`"session_token":\s*"([A-Za-z0-9+/=]+)"`)

	if matches := accessKeyJSONRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.AccessKeyID = matches[1]
	}

	if matches := secretKeyJSONRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.SecretAccessKey = matches[1]
	}

	if matches := sessionTokenJSONRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.SessionToken = matches[1]
	}

	return creds.AccessKeyID != "" && creds.SecretAccessKey != ""
}

// tryPythonDictFormat attempts to parse Python dict format with single quotes
func tryPythonDictFormat(text string, creds *ExtractedCredentials) bool {
	accessKeyPyRegex := regexp.MustCompile(`'access_key_id':\s*'([A-Z0-9]+)'`)
	secretKeyPyRegex := regexp.MustCompile(`'secret_access_key':\s*'([A-Za-z0-9+/=]+)'`)
	sessionTokenPyRegex := regexp.MustCompile(`'session_token':\s*'([A-Za-z0-9+/=]+)'`)

	if matches := accessKeyPyRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.AccessKeyID = matches[1]
	}

	if matches := secretKeyPyRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.SecretAccessKey = matches[1]
	}

	if matches := sessionTokenPyRegex.FindStringSubmatch(text); len(matches) > 1 {
		creds.SessionToken = matches[1]
	}

	return creds.AccessKeyID != "" && creds.SecretAccessKey != ""
}

// tryBase64Decode attempts to base64 decode the text
// Returns the decoded text and nil error on success
// Returns original text and error if decode fails
func tryBase64Decode(text string) (string, error) {
	// Trim whitespace
	text = strings.TrimSpace(text)

	// Try standard base64 decoding
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err == nil && len(decoded) > 0 {
		return string(decoded), nil
	}

	// Try URL-safe base64 decoding
	decoded, err = base64.URLEncoding.DecodeString(text)
	if err == nil && len(decoded) > 0 {
		return string(decoded), nil
	}

	// Try raw standard base64 (without padding)
	decoded, err = base64.RawStdEncoding.DecodeString(text)
	if err == nil && len(decoded) > 0 {
		return string(decoded), nil
	}

	// Try raw URL-safe base64 (without padding)
	decoded, err = base64.RawURLEncoding.DecodeString(text)
	if err == nil && len(decoded) > 0 {
		return string(decoded), nil
	}

	return text, fmt.Errorf("failed to decode base64")
}

func ExtractCredentialsFromText(text string) (*ExtractedCredentials, error) {
	creds := &ExtractedCredentials{}

	// Try multiple parsing methods in order of preference
	parsers := []func(string, *ExtractedCredentials) bool{
		tryEnvVarFormat,
		tryJSONFormat,
		tryPythonDictFormat,
	}

	found := false
	parsedText := text // Track which text was successfully parsed

	for _, parser := range parsers {
		if parser(text, creds) {
			found = true
			break
		}
	}

	// If no format worked, try base64 decoding and parse again
	if !found {
		decoded, err := tryBase64Decode(text)
		if err == nil && decoded != text {
			// Successfully decoded, try parsers again on decoded text
			for _, parser := range parsers {
				if parser(decoded, creds) {
					found = true
					parsedText = decoded // Use decoded text for region/source extraction
					break
				}
			}
		}
	}

	// Extract region if available - try multiple formats on the text that was parsed
	regionRegex := regexp.MustCompile(`Region:\s*([a-z0-9-]+)`)
	regionJSONRegex := regexp.MustCompile(`"region":\s*"([a-z0-9-]+)"`)
	regionPyRegex := regexp.MustCompile(`'region':\s*'([a-z0-9-]+)'`)

	if matches := regionRegex.FindStringSubmatch(parsedText); len(matches) > 1 {
		creds.Region = matches[1]
	} else if matches := regionJSONRegex.FindStringSubmatch(parsedText); len(matches) > 1 {
		creds.Region = matches[1]
	} else if matches := regionPyRegex.FindStringSubmatch(parsedText); len(matches) > 1 {
		creds.Region = matches[1]
	} else {
		// Default region
		creds.Region = "us-east-1"
	}

	// Determine source type from the text that was parsed
	if strings.Contains(strings.ToLower(parsedText), "lambda") {
		creds.Source = "lambda"
	} else if strings.Contains(strings.ToLower(parsedText), "ec2") {
		creds.Source = "ec2"
	} else {
		creds.Source = "exploit"
	}

	if !found {
		return nil, fmt.Errorf("no AWS credentials found in the provided text")
	}

	// Validate that we have at least access key and secret key
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("incomplete credentials: missing access key or secret key")
	}

	return creds, nil
}

func (c *ExtractedCredentials) GenerateIdentityName() string {
	suffix := c.AccessKeyID
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}

	return fmt.Sprintf("%s_%s", c.Source, suffix)
}