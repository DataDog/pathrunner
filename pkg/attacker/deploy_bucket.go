package attacker

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// DeployBucket creates a code-hosting or exfil bucket in the attacker account
// and tracks it in deploy state. Wraps the existing S3 primitives.
func DeployBucket(attackerCfg aws.Config, victimAccountID string, region string, bucketType string) (string, error) {
	var bucketName string
	var err error

	switch bucketType {
	case "code":
		bucketName, err = CreateCodeHostingBucket(attackerCfg, victimAccountID, region)
	case "exfil":
		bucketName, err = CreateExfilBucket(attackerCfg, victimAccountID, region)
	default:
		return "", fmt.Errorf("unknown bucket type: %s. Use 'code' or 'exfil'", bucketType)
	}

	if err != nil {
		return "", err
	}

	// Track in deploy state
	state, err := LoadDeployState()
	if err != nil {
		return bucketName, fmt.Errorf("bucket created (%s) but failed to load deploy state: %v", bucketName, err)
	}

	state.Buckets = append(state.Buckets, BucketDeployState{
		Name:   bucketName,
		Type:   bucketType,
		Region: region,
	})

	if err := SaveDeployState(state); err != nil {
		return bucketName, fmt.Errorf("bucket created (%s) but failed to save deploy state: %v", bucketName, err)
	}

	return bucketName, nil
}

// DestroyBucket deletes a specific bucket and removes it from deploy state.
func DestroyBucket(attackerCfg aws.Config, bucketName string) error {
	state, err := LoadDeployState()
	if err != nil {
		return err
	}

	// Find the bucket in state to get its region
	var targetBucket *BucketDeployState
	var targetIndex int
	for i, b := range state.Buckets {
		if b.Name == bucketName {
			targetBucket = &state.Buckets[i]
			targetIndex = i
			break
		}
	}

	if targetBucket == nil {
		return fmt.Errorf("bucket '%s' not found in deploy state", bucketName)
	}

	// Delete the bucket
	if err := DeleteBucket(attackerCfg, bucketName, targetBucket.Region); err != nil {
		return err
	}

	// Remove from state
	state.Buckets = append(state.Buckets[:targetIndex], state.Buckets[targetIndex+1:]...)

	if state.HasAnyDeployedResources() {
		return SaveDeployState(state)
	}
	return RemoveDeployState()
}

// DestroyAllBuckets deletes all tracked buckets.
func DestroyAllBuckets(attackerCfg aws.Config) error {
	state, err := LoadDeployState()
	if err != nil {
		return err
	}

	if len(state.Buckets) == 0 {
		return fmt.Errorf("no tracked buckets to destroy")
	}

	var lastErr error
	for _, b := range state.Buckets {
		fmt.Printf("[*] Deleting bucket %s...\n", b.Name)
		if err := DeleteBucket(attackerCfg, b.Name, b.Region); err != nil {
			fmt.Printf("[!] Failed to delete %s: %v\n", b.Name, err)
			lastErr = err
		}
	}

	state.Buckets = nil
	if state.HasAnyDeployedResources() {
		SaveDeployState(state)
	} else {
		RemoveDeployState()
	}

	return lastErr
}

// ListDeployedBuckets returns all tracked buckets from deploy state.
func ListDeployedBuckets() ([]BucketDeployState, error) {
	state, err := LoadDeployState()
	if err != nil {
		return nil, err
	}
	return state.Buckets, nil
}
