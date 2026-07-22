// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DeployState tracks all deployed attacker infrastructure. Persisted to
// ~/.pathrunner/deploy.json across workspaces since attacker infra is shared.
type DeployState struct {
	EC2      *EC2DeployState      `json:"ec2,omitempty"`
	Buckets  []BucketDeployState  `json:"buckets,omitempty"`
	ECRRepos []ECRRepoDeployState `json:"ecr_repos,omitempty"`
}

// EC2DeployState tracks a deployed pathrunner EC2 instance and its associated resources.
type EC2DeployState struct {
	InstanceID         string `json:"instance_id"`
	Region             string `json:"region"`
	PublicIP           string `json:"public_ip"`
	SecurityGroupID    string `json:"security_group_id"`
	KeyPairName        string `json:"key_pair_name"`
	KeyFilePath        string `json:"key_file_path"`
	InstanceProfileARN string `json:"instance_profile_arn,omitempty"`
	RoleName           string `json:"role_name,omitempty"`
	ProfileName        string `json:"profile_name,omitempty"`
}

// BucketDeployState tracks a deployed attacker S3 bucket.
type BucketDeployState struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"` // "code" or "exfil"
	Region        string   `json:"region"`
	AccountIDs    []string `json:"account_ids"`     // victim account IDs granted access via resource policy
	CollectedKeys []string `json:"collected_keys"`  // exfil artifact keys already imported
}

// ECRRepoDeployState tracks a deployed attacker ECR repository. The repo is
// generic infrastructure -- modules push their own service-specific images.
type ECRRepoDeployState struct {
	RepositoryName string   `json:"repository_name"`
	RepositoryURI  string   `json:"repository_uri"` // e.g., 123456789012.dkr.ecr.us-east-1.amazonaws.com/pathrunner-runtime
	Region         string   `json:"region"`
	AccountIDs     []string `json:"account_ids"` // victim account IDs granted pull access via repo policy
}

// deployStatePath returns the path to the deploy state file.
func deployStatePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	return filepath.Join(homeDir, ".pathrunner", "deploy.json"), nil
}

// LoadDeployState reads the deploy state from disk. Returns an empty state if
// the file doesn't exist yet.
func LoadDeployState() (*DeployState, error) {
	path, err := deployStatePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &DeployState{}, nil
		}
		return nil, fmt.Errorf("failed to read deploy state: %v", err)
	}

	var state DeployState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse deploy state: %v", err)
	}

	return &state, nil
}

// SaveDeployState writes the deploy state to disk. Creates the directory if needed.
func SaveDeployState(state *DeployState) error {
	path, err := deployStatePath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal deploy state: %v", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write deploy state: %v", err)
	}

	return nil
}

// GetCollectedExfilKeys returns the set of S3 object keys already imported by
// bucket collect, so subsequent runs can skip them.
func GetCollectedExfilKeys() map[string]bool {
	state, err := LoadDeployState()
	if err != nil {
		return nil
	}
	for _, b := range state.Buckets {
		if b.Type == "exfil" {
			set := make(map[string]bool, len(b.CollectedKeys))
			for _, k := range b.CollectedKeys {
				set[k] = true
			}
			return set
		}
	}
	return nil
}

// MarkExfilKeyCollected records that an exfil artifact has been imported so
// subsequent bucket collect runs skip it.
func MarkExfilKeyCollected(key string) error {
	state, err := LoadDeployState()
	if err != nil {
		return err
	}
	for i, b := range state.Buckets {
		if b.Type == "exfil" {
			for _, k := range b.CollectedKeys {
				if k == key {
					return nil // already recorded
				}
			}
			state.Buckets[i].CollectedKeys = append(state.Buckets[i].CollectedKeys, key)
			return SaveDeployState(state)
		}
	}
	return nil
}

// RemoveDeployState deletes the deploy state file from disk.
func RemoveDeployState() error {
	path, err := deployStatePath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove deploy state: %v", err)
	}
	return nil
}

// HasAnyDeployedResources returns true if there are any deployed resources tracked.
func (s *DeployState) HasAnyDeployedResources() bool {
	return s.EC2 != nil || len(s.Buckets) > 0 || len(s.ECRRepos) > 0
}
