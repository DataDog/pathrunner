package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// DiscoverS3Buckets lists S3 buckets accessible to the current identity.
// Returns choices with bucket names as values.
func DiscoverS3Buckets(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := s3.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := client.ListBuckets(listCtx, &s3.ListBucketsInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("BUCKET", "s3:ListAllMyBuckets", err))
		}
		return nil, fmt.Errorf("failed to list S3 buckets: %v", err)
	}

	if len(result.Buckets) == 0 {
		return nil, nil
	}

	var choices []modules.DiscoveryChoice
	for _, bucket := range result.Buckets {
		bucketName := aws.ToString(bucket.Name)
		label := bucketName
		if bucket.CreationDate != nil {
			label = fmt.Sprintf("%s (created: %s)", bucketName, bucket.CreationDate.Format("2006-01-02"))
		}
		choices = append(choices, modules.DiscoveryChoice{
			Value: bucketName,
			Label: label,
		})
	}

	return choices, nil
}
