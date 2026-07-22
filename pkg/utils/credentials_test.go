// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package utils

import (
	"testing"
)

func TestExtractCredentialsFromText(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectSuccess  bool
		expectedKeyID  string
		expectedSecret string
		expectedToken  string
		expectedRegion string
		expectedSource string
	}{
		{
			name: "Environment variable format",
			input: `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_SESSION_TOKEN=FwoGZXIvYXdzEBEaDGNvbnNvbGVfdGVzdCKZAtest
Region: us-west-2
This is from a lambda function
`,
			expectSuccess:  true,
			expectedKeyID:  "AKIAIOSFODNN7EXAMPLE",
			expectedSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedToken:  "FwoGZXIvYXdzEBEaDGNvbnNvbGVfdGVzdCKZAtest",
			expectedRegion: "us-west-2",
			expectedSource: "lambda",
		},
		{
			name: "JSON format with double quotes",
			input: `{
  "credentials": {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "session_token": "FwoGZXIvYXdzEBEaDGNvbnNvbGVfdGVzdCKZAtest"
  },
  "region": "eu-west-1"
}`,
			expectSuccess:  true,
			expectedKeyID:  "AKIAIOSFODNN7EXAMPLE",
			expectedSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedToken:  "FwoGZXIvYXdzEBEaDGNvbnNvbGVfdGVzdCKZAtest",
			expectedRegion: "eu-west-1",
			expectedSource: "exploit",
		},
		{
			name: "Python dict format with single quotes (simple)",
			input: `{'type': 'lambda_credential_exfil', 'credentials': {'access_key_id': 'ASIAIOSFODNN7EXAMPLE', 'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'session_token': 'IQoJb3JpZ2luX2VjEH8aCXVzLXdlc3QtMiJHMEUCIGWDsnDXu/jUhRJlgFRFBVuiroeXwJpFkW1tDhYR5ZTnAiEA+aSZefM9n4gxJ8Z+gba7ZVxWT4+xqjVz+B9T3czCc64q5AIIFxAAGgw1OTAxODQwNDE4MTgiDAPGqG2DHDdsP68LBSrBAiQEQymrKBT6BzPfmEjQBnolCFR/F7GK6C1mgRj9ieBgMRP5PL1/J3dOYRBSu58PpEk71YYyYS6nKDVNfDzQiWCVUx2lzVatBORX89eagH+0vfoPPpQVyd8XGNjHKuuZ3z9H8IaxriLZK7FBEDmyKLC6ySCzbi1nAyWAB5fl3D507mNI7sv4PJsZEx5sYCsU9U0SmXw5uLwvGPX6VgfRh3HBpFXEoNAzetgSg6fdHvkXig8EL61bZqFbHYbwCRX24xUcUpx9MJ2W3sNgZinyWma9yf8mY3avQ6XI0vHwYyW/C6BAOOZ/1s7wDIi9njhvpCecz2Ai6J4Yt/pTRlXInrW+hO4jT5h+/Me77g6h4SOCWdveVKaI8GzLYq09SbAmxfAoW1G/Z8cpF+uKa9QQmPopB9AAjwpWxsW9AQ9pP3xT2DDB8PTGBjqeATXAJ/o0cygWaZ1+K3S119teAg+sBvYdxcMLXWM3VQxRO/PfsGLUxYC7RZpm4zINxMMKgAWkA13lirLJdQkySko49m6O5LPhW/DEo0djricXa3jGsDUZ0VAQq/KeV4u9vzpvezWRcMP5O9zgIHfRyn8fXECn0Qa8FCp2ozxU1gABVGJVaWkC6OKuTfOTsuq0vbJfqLlxYwhA/61+1MZW'}, 'region': 'us-west-2'}`,
			expectSuccess:  true,
			expectedKeyID:  "ASIAIOSFODNN7EXAMPLE",
			expectedSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedToken:  "IQoJb3JpZ2luX2VjEH8aCXVzLXdlc3QtMiJHMEUCIGWDsnDXu/jUhRJlgFRFBVuiroeXwJpFkW1tDhYR5ZTnAiEA+aSZefM9n4gxJ8Z+gba7ZVxWT4+xqjVz+B9T3czCc64q5AIIFxAAGgw1OTAxODQwNDE4MTgiDAPGqG2DHDdsP68LBSrBAiQEQymrKBT6BzPfmEjQBnolCFR/F7GK6C1mgRj9ieBgMRP5PL1/J3dOYRBSu58PpEk71YYyYS6nKDVNfDzQiWCVUx2lzVatBORX89eagH+0vfoPPpQVyd8XGNjHKuuZ3z9H8IaxriLZK7FBEDmyKLC6ySCzbi1nAyWAB5fl3D507mNI7sv4PJsZEx5sYCsU9U0SmXw5uLwvGPX6VgfRh3HBpFXEoNAzetgSg6fdHvkXig8EL61bZqFbHYbwCRX24xUcUpx9MJ2W3sNgZinyWma9yf8mY3avQ6XI0vHwYyW/C6BAOOZ/1s7wDIi9njhvpCecz2Ai6J4Yt/pTRlXInrW+hO4jT5h+/Me77g6h4SOCWdveVKaI8GzLYq09SbAmxfAoW1G/Z8cpF+uKa9QQmPopB9AAjwpWxsW9AQ9pP3xT2DDB8PTGBjqeATXAJ/o0cygWaZ1+K3S119teAg+sBvYdxcMLXWM3VQxRO/PfsGLUxYC7RZpm4zINxMMKgAWkA13lirLJdQkySko49m6O5LPhW/DEo0djricXa3jGsDUZ0VAQq/KeV4u9vzpvezWRcMP5O9zgIHfRyn8fXECn0Qa8FCp2ozxU1gABVGJVaWkC6OKuTfOTsuq0vbJfqLlxYwhA/61+1MZW",
			expectedRegion: "us-west-2",
			expectedSource: "lambda",
		},
		{
			name:           "Real Lambda HTTPS exfil output - full JSON",
			input:          `JSON: {'type': 'lambda_credential_exfil', 'timestamp': '00000000-0000-0000-0000-000000000000', 'caller_identity': {'account': '123456789012', 'arn': 'arn:aws:sts::123456789012:assumed-role/example-role-ExampleRole-EXAMPLEID1234/c2-test6', 'user_id': 'AROAIOSFODNN7EXAMPLE:c2-test6'}, 'region': 'us-west-2', 'function_info': {'name': 'c2-test6', 'version': '$LATEST', 'memory_limit': '128', 'log_group': '/aws/lambda/c2-test6', 'log_stream': '2025/10/01/[$LATEST]example00000000000000000000000000000'}, 'credentials': {'access_key_id': 'ASIAIOSFODNN7EXAMPLE', 'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'session_token': 'IQoJb3JpZ2luX2VjEH8aCXVzLXdlc3QtMiJHMEUCIGWDsnDXu/jUhRJlgFRFBVuiroeXwJpFkW1tDhYR5ZTnAiEA+aSZefM9n4gxJ8Z+gba7ZVxWT4+xqjVz+B9T3czCc64q5AIIFxAAGgw1OTAxODQwNDE4MTgiDAPGqG2DHDdsP68LBSrBAiQEQymrKBT6BzPfmEjQBnolCFR/F7GK6C1mgRj9ieBgMRP5PL1/J3dOYRBSu58PpEk71YYyYS6nKDVNfDzQiWCVUx2lzVatBORX89eagH+0vfoPPpQVyd8XGNjHKuuZ3z9H8IaxriLZK7FBEDmyKLC6ySCzbi1nAyWAB5fl3D507mNI7sv4PJsZEx5sYCsU9U0SmXw5uLwvGPX6VgfRh3HBpFXEoNAzetgSg6fdHvkXig8EL61bZqFbHYbwCRX24xUcUpx9MJ2W3sNgZinyWma9yf8mY3avQ6XI0vHwYyW/C6BAOOZ/1s7wDIi9njhvpCecz2Ai6J4Yt/pTRlXInrW+hO4jT5h+/Me77g6h4SOCWdveVKaI8GzLYq09SbAmxfAoW1G/Z8cpF+uKa9QQmPopB9AAjwpWxsW9AQ9pP3xT2DDB8PTGBjqeATXAJ/o0cygWaZ1+K3S119teAg+sBvYdxcMLXWM3VQxRO/PfsGLUxYC7RZpm4zINxMMKgAWkA13lirLJdQkySko49m6O5LPhW/DEo0djricXa3jGsDUZ0VAQq/KeV4u9vzpvezWRcMP5O9zgIHfRyn8fXECn0Qa8FCp2ozxU1gABVGJVaWkC6OKuTfOTsuq0vbJfqLlxYwhA/61+1MZW'}}`,
			expectSuccess:  true,
			expectedKeyID:  "ASIAIOSFODNN7EXAMPLE",
			expectedSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedToken:  "IQoJb3JpZ2luX2VjEH8aCXVzLXdlc3QtMiJHMEUCIGWDsnDXu/jUhRJlgFRFBVuiroeXwJpFkW1tDhYR5ZTnAiEA+aSZefM9n4gxJ8Z+gba7ZVxWT4+xqjVz+B9T3czCc64q5AIIFxAAGgw1OTAxODQwNDE4MTgiDAPGqG2DHDdsP68LBSrBAiQEQymrKBT6BzPfmEjQBnolCFR/F7GK6C1mgRj9ieBgMRP5PL1/J3dOYRBSu58PpEk71YYyYS6nKDVNfDzQiWCVUx2lzVatBORX89eagH+0vfoPPpQVyd8XGNjHKuuZ3z9H8IaxriLZK7FBEDmyKLC6ySCzbi1nAyWAB5fl3D507mNI7sv4PJsZEx5sYCsU9U0SmXw5uLwvGPX6VgfRh3HBpFXEoNAzetgSg6fdHvkXig8EL61bZqFbHYbwCRX24xUcUpx9MJ2W3sNgZinyWma9yf8mY3avQ6XI0vHwYyW/C6BAOOZ/1s7wDIi9njhvpCecz2Ai6J4Yt/pTRlXInrW+hO4jT5h+/Me77g6h4SOCWdveVKaI8GzLYq09SbAmxfAoW1G/Z8cpF+uKa9QQmPopB9AAjwpWxsW9AQ9pP3xT2DDB8PTGBjqeATXAJ/o0cygWaZ1+K3S119teAg+sBvYdxcMLXWM3VQxRO/PfsGLUxYC7RZpm4zINxMMKgAWkA13lirLJdQkySko49m6O5LPhW/DEo0djricXa3jGsDUZ0VAQq/KeV4u9vzpvezWRcMP5O9zgIHfRyn8fXECn0Qa8FCp2ozxU1gABVGJVaWkC6OKuTfOTsuq0vbJfqLlxYwhA/61+1MZW",
			expectedRegion: "us-west-2",
			expectedSource: "lambda",
		},
		{
			name: "Only access key and secret, no token",
			input: `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
			expectSuccess:  true,
			expectedKeyID:  "AKIAIOSFODNN7EXAMPLE",
			expectedSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedToken:  "",
			expectedRegion: "us-east-1", // default
			expectedSource: "exploit",
		},
		{
			name:          "No credentials at all",
			input:         "This is just some random text with no credentials",
			expectSuccess: false,
		},
		{
			name: "Missing secret key",
			input: `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
`,
			expectSuccess: false,
		},
		{
			name:           "Base64 encoded environment variables",
			input:          `QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQUlPU0ZPRE5ON0VYQU1QTEUKQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPXdKYWxyWFV0bkZFTUkvSzdNREVORy9iUHhSZmlDWUVYQU1QTEVLRVkKQVdTX1NFU1NJT05fVE9LRU49RndvR1pYSXZZWGR6RUJFYURHTnZibk52YkdWZmRHVnpkQ0taQXRlc3QKUmVnaW9uOiB1cy1lYXN0LTE=`,
			expectSuccess:  true,
			expectedKeyID:  "AKIAIOSFODNN7EXAMPLE",
			expectedSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedToken:  "FwoGZXIvYXdzEBEaDGNvbnNvbGVfdGVzdCKZAtest",
			expectedRegion: "us-east-1",
			expectedSource: "exploit",
		},
		{
			name:           "Base64 encoded JSON",
			input:          `eyJjcmVkZW50aWFscyI6IHsiYWNjZXNzX2tleV9pZCI6ICJBS0lBSU9TRk9ETk43RVhBTVBMRSIsICJzZWNyZXRfYWNjZXNzX2tleSI6ICJ3SmFsclhVdG5GRU1JL0s3TURFTkcvYlB4UmZpQ1lFWEFNUExFS0VZIiwgInNlc3Npb25fdG9rZW4iOiAiRndvR1pYSXZZWGR6RUJFYURHTnZibk52YkdWZmRHVnpkQ0taQXRlc3QifSwgInJlZ2lvbiI6ICJldS13ZXN0LTEifQ==`,
			expectSuccess:  true,
			expectedKeyID:  "AKIAIOSFODNN7EXAMPLE",
			expectedSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedToken:  "FwoGZXIvYXdzEBEaDGNvbnNvbGVfdGVzdCKZAtest",
			expectedRegion: "eu-west-1",
			expectedSource: "exploit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := ExtractCredentialsFromText(tt.input)

			if tt.expectSuccess {
				if err != nil {
					t.Errorf("Expected success but got error: %v", err)
					return
				}

				if creds.AccessKeyID != tt.expectedKeyID {
					t.Errorf("AccessKeyID mismatch:\nExpected: %s\nGot:      %s", tt.expectedKeyID, creds.AccessKeyID)
				}

				if creds.SecretAccessKey != tt.expectedSecret {
					t.Errorf("SecretAccessKey mismatch:\nExpected: %s\nGot:      %s", tt.expectedSecret, creds.SecretAccessKey)
				}

				if creds.SessionToken != tt.expectedToken {
					t.Errorf("SessionToken mismatch:\nExpected: %s\nGot:      %s", tt.expectedToken, creds.SessionToken)
				}

				if creds.Region != tt.expectedRegion {
					t.Errorf("Region mismatch:\nExpected: %s\nGot:      %s", tt.expectedRegion, creds.Region)
				}

				if creds.Source != tt.expectedSource {
					t.Errorf("Source mismatch:\nExpected: %s\nGot:      %s", tt.expectedSource, creds.Source)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error but got success")
				}
			}
		})
	}
}
