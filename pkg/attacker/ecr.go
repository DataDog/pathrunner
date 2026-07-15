package attacker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// DefaultECRRepoName is the default repository name for attacker container images.
// ECR repos are account-scoped, so no random suffix is needed (unlike S3 buckets).
const DefaultECRRepoName = "pathrunner-runtime"

// CreateECRRepository creates an ECR repository in the attacker account.
// Returns the repository URI (e.g., 123456789012.dkr.ecr.us-east-1.amazonaws.com/pathrunner-bedrock-runtime).
func CreateECRRepository(attackerCfg aws.Config, repoName string, region string) (string, error) {
	cfg := attackerCfg.Copy()
	cfg.Region = region

	client := ecr.NewFromConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	output, err := client.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName:     aws.String(repoName),
		ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create ECR repository: %v", err)
	}

	return aws.ToString(output.Repository.RepositoryUri), nil
}

// SetECRPullPolicy sets a repository policy granting the specified victim accounts
// permission to pull images. This enables cross-account image pulls by Bedrock
// AgentCore Runtime running in the victim account.
func SetECRPullPolicy(attackerCfg aws.Config, repoName string, accountIDs []string, region string) error {
	if len(accountIDs) == 0 {
		return nil
	}

	cfg := attackerCfg.Copy()
	cfg.Region = region

	policyJSON, err := buildECRPullPolicy(accountIDs)
	if err != nil {
		return err
	}

	client := ecr.NewFromConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = client.SetRepositoryPolicy(ctx, &ecr.SetRepositoryPolicyInput{
		RepositoryName: aws.String(repoName),
		PolicyText:     aws.String(policyJSON),
	})
	if err != nil {
		return fmt.Errorf("failed to set ECR repository policy: %v", err)
	}

	return nil
}

// buildECRPullPolicy constructs a JSON repository policy granting cross-account
// pull access to the specified AWS account IDs.
func buildECRPullPolicy(accountIDs []string) (string, error) {
	principals := make([]string, len(accountIDs))
	for i, accountID := range accountIDs {
		principals[i] = fmt.Sprintf("arn:aws:iam::%s:root", accountID)
	}

	// ECR repo policies accept a single string or an array for Principal.AWS.
	var principalValue any
	if len(principals) == 1 {
		principalValue = principals[0]
	} else {
		principalValue = principals
	}

	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Sid":    "AllowVictimPull",
				"Effect": "Allow",
				"Principal": map[string]any{
					"AWS": principalValue,
				},
				"Action": []string{
					"ecr:GetDownloadUrlForLayer",
					"ecr:BatchGetImage",
					"ecr:BatchCheckLayerAvailability",
				},
			},
		},
	}

	data, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ECR policy: %v", err)
	}

	return string(data), nil
}

// DeleteECRRepository force-deletes an ECR repository and all its images.
func DeleteECRRepository(attackerCfg aws.Config, repoName string, region string) error {
	cfg := attackerCfg.Copy()
	cfg.Region = region

	client := ecr.NewFromConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.DeleteRepository(ctx, &ecr.DeleteRepositoryInput{
		RepositoryName: aws.String(repoName),
		Force:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to delete ECR repository: %v", err)
	}

	return nil
}

// ECRAuthCredentials holds the decoded ECR authentication token.
type ECRAuthCredentials struct {
	Username string
	Password string
	Endpoint string // e.g., https://123456789012.dkr.ecr.us-east-1.amazonaws.com
}

// GetECRAuthToken retrieves an ECR authorization token and decodes it into
// a username/password pair suitable for `docker login`.
func GetECRAuthToken(attackerCfg aws.Config, region string) (*ECRAuthCredentials, error) {
	cfg := attackerCfg.Copy()
	cfg.Region = region

	client := ecr.NewFromConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	output, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ECR authorization token: %v", err)
	}

	if len(output.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no authorization data returned from ECR")
	}

	authData := output.AuthorizationData[0]

	// The token is base64-encoded "username:password"
	decoded, err := base64.StdEncoding.DecodeString(aws.ToString(authData.AuthorizationToken))
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECR auth token: %v", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected ECR auth token format")
	}

	return &ECRAuthCredentials{
		Username: parts[0],
		Password: parts[1],
		Endpoint: aws.ToString(authData.ProxyEndpoint),
	}, nil
}
