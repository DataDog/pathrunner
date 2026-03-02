package modules

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Option struct {
	Name        string
	Description string
	Required    bool
	Default     string
}

type Identity struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Profile     string            `json:"profile,omitempty"`
	AccessKeyID string            `json:"access_key_id,omitempty"`
	SecretKey   string            `json:"secret_key,omitempty"`
	SessionToken string           `json:"session_token,omitempty"`
	Region      string            `json:"region,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	config      aws.Config        `json:"-"`
}

func (i *Identity) IsExpired() bool {
	if i.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*i.ExpiresAt)
}

func (i *Identity) Validate() error {
	if i.IsExpired() {
		return fmt.Errorf("credentials have expired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use GetConfig() to ensure fresh credentials for profiles
	cfg := i.GetConfig()
	stsClient := sts.NewFromConfig(cfg)
	_, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("credential validation failed: %v", err)
	}

	return nil
}

func (i *Identity) GetConfig() aws.Config {
	// For profile identities, create fresh config to avoid stale credentials
	if i.Type == "profile" && i.Profile != "" {
		// Load config with region override if specified
		opts := []func(*config.LoadOptions) error{config.WithSharedConfigProfile(i.Profile)}
		if i.Region != "" {
			opts = append(opts, config.WithRegion(i.Region))
		}
		cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
		if err != nil {
			// Fallback to stored config on error
			return i.config
		}
		return cfg
	}

	// For key-based identities, ensure config has credentials and region
	if i.Type == "keys" || i.Type == "assumed_role" || i.Type == "env" {
		// If config is not set or doesn't have credentials, rebuild it
		if i.config.Credentials == nil || i.config.Region == "" {
			creds := credentials.NewStaticCredentialsProvider(i.AccessKeyID, i.SecretKey, i.SessionToken)
			cfg, err := config.LoadDefaultConfig(context.Background(),
				config.WithCredentialsProvider(creds),
				config.WithRegion(i.Region),
			)
			if err == nil {
				i.config = cfg
				return cfg
			}
		}
	}

	// Ensure region is set in config
	if i.config.Region == "" && i.Region != "" {
		i.config.Region = i.Region
	}

	return i.config
}

func (i *Identity) GetAWSCredentials(ctx context.Context) (aws.Credentials, error) {
	// Use GetConfig() to ensure fresh credentials for profiles
	cfg := i.GetConfig()
	return cfg.Credentials.Retrieve(ctx)
}

func (i *Identity) SetConfig(config aws.Config) {
	i.config = config
}

func (i *Identity) RefreshConfig() error {
	switch i.Type {
	case "profile":
		if i.Profile == "" {
			return fmt.Errorf("profile name is empty")
		}
		// Load config with region override if specified
		opts := []func(*config.LoadOptions) error{config.WithSharedConfigProfile(i.Profile)}
		if i.Region != "" {
			opts = append(opts, config.WithRegion(i.Region))
		}
		cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
		if err != nil {
			return fmt.Errorf("failed to refresh profile config: %v", err)
		}
		i.config = cfg
		return nil

	case "env":
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return fmt.Errorf("failed to refresh environment config: %v", err)
		}
		if i.Region != "" {
			cfg.Region = i.Region
		}
		i.config = cfg
		return nil

	case "keys":
		if i.AccessKeyID == "" || i.SecretKey == "" {
			return fmt.Errorf("access key or secret key is empty")
		}
		creds := credentials.NewStaticCredentialsProvider(i.AccessKeyID, i.SecretKey, i.SessionToken)
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithCredentialsProvider(creds))
		if err != nil {
			return fmt.Errorf("failed to refresh keys config: %v", err)
		}
		if i.Region != "" {
			cfg.Region = i.Region
		}
		i.config = cfg
		return nil

	default:
		return fmt.Errorf("unknown identity type: %s", i.Type)
	}
}

type Module interface {
	Name() string
	Description() string
	Options() []Option
	PayloadOptions(payload string) []Option
	ListPayloads() []PayloadInfo
	Execute(identity *Identity, options map[string]string, tracker ResourceTracker) (string, error)
}

// PayloadCompatible is an optional interface that modules can implement
// to declare their payload compatibility and enable automatic filtering
type PayloadCompatible interface {
	// GetCompatibleTags returns the payload tags this module supports
	// e.g., ["lambda", "python"] for Lambda-based modules
	GetCompatibleTags() []string

	// GetPayloadContext returns the primary service context
	// e.g., "lambda", "ec2", "apprunner"
	GetPayloadContext() string
}

type PayloadInfo struct {
	Name        string
	Description string
}

type CreatedResource struct {
	Type          string            `json:"type"`
	Name          string            `json:"name"`
	ARN           string            `json:"arn,omitempty"`
	Region        string            `json:"region"`
	Created       time.Time         `json:"created"`
	CleanupMethod string            `json:"cleanup_method"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type ResourceTracker interface {
	TrackResource(resource CreatedResource)
}