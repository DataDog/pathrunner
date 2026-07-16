package attacker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucketName)})
		return "", fmt.Errorf("failed to marshal bucket policy: %v", err)
	}

	resolvedPolicy := replaceBucketPlaceholder(string(policyJSON), bucketName)

	_, err = s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(resolvedPolicy),
	})
	if err != nil {
		s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucketName)})
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

func generateBucketName(prefix string) (string, error) {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(randomBytes)), nil
}
