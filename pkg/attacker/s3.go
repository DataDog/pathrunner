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

	"pathrunner/pkg/modules"
)

// CreateCodeHostingBucket creates an S3 bucket in the attacker account with a
// resource-based policy granting the victim account read access. Returns the
// bucket name for modules to upload payloads to.
func CreateCodeHostingBucket(attackerCfg aws.Config, victimAccountID string, region string) (string, error) {
	bucketName, err := generateBucketName()
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

	// Set resource policy granting victim account read access
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":    "AllowVictimRead",
				"Effect": "Allow",
				"Principal": map[string]string{
					"AWS": fmt.Sprintf("arn:aws:iam::%s:root", victimAccountID),
				},
				"Action": []string{
					"s3:GetObject",
					"s3:GetBucketLocation",
					"s3:ListBucket",
				},
				"Resource": []string{
					fmt.Sprintf("arn:aws:s3:::%s", bucketName),
					fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
				},
			},
		},
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal bucket policy: %v", err)
	}

	_, err = s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(string(policyJSON)),
	})
	if err != nil {
		// Try to clean up the bucket if policy fails
		s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucketName)})
		return "", fmt.Errorf("failed to set bucket policy: %v", err)
	}

	return bucketName, nil
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

func generateBucketName() (string, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("pathrunner-%s", hex.EncodeToString(bytes)), nil
}

