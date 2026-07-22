// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// DeployBucket creates a code-hosting or exfil bucket in the attacker account
// and tracks it in deploy state. Wraps the existing S3 primitives.
func DeployBucket(attackerCfg aws.Config, victimAccountIDs []string, region string, bucketType string) (string, error) {
	var bucketName string
	var err error

	switch bucketType {
	case "code":
		bucketName, err = CreateCodeHostingBucket(attackerCfg, victimAccountIDs, region)
	case "exfil":
		bucketName, err = CreateExfilBucket(attackerCfg, victimAccountIDs, region)
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
		Name:       bucketName,
		Type:       bucketType,
		Region:     region,
		AccountIDs: victimAccountIDs,
	})

	if err := SaveDeployState(state); err != nil {
		return bucketName, fmt.Errorf("bucket created (%s) but failed to save deploy state: %v", bucketName, err)
	}

	return bucketName, nil
}

// EnsureBucketAccountAccess checks if the given account ID already has access
// to all deployed buckets. If not, updates bucket policies and deploy state.
// Returns the number of buckets updated.
func EnsureBucketAccountAccess(attackerCfg aws.Config, newAccountID string) (int, error) {
	state, err := LoadDeployState()
	if err != nil {
		return 0, err
	}

	if len(state.Buckets) == 0 {
		return 0, nil
	}

	updated := 0
	for i := range state.Buckets {
		bucket := &state.Buckets[i]

		// Check if this account already has access
		hasAccess := false
		for _, existingID := range bucket.AccountIDs {
			if existingID == newAccountID {
				hasAccess = true
				break
			}
		}
		if hasAccess {
			continue
		}

		// Add the new account ID and update the policy
		bucket.AccountIDs = append(bucket.AccountIDs, newAccountID)
		if err := UpdateBucketPolicyForAccounts(attackerCfg, bucket.Name, bucket.Type, bucket.AccountIDs, bucket.Region); err != nil {
			return updated, fmt.Errorf("failed to update policy for bucket '%s': %v", bucket.Name, err)
		}
		updated++
	}

	if updated > 0 {
		if err := SaveDeployState(state); err != nil {
			return updated, fmt.Errorf("bucket policies updated but failed to save deploy state: %v", err)
		}
	}

	return updated, nil
}

// GetExfilBucket returns the name of the first deployed exfil bucket, or empty
// string if none exists. Used by modules to auto-populate EXFIL_BUCKET.
func GetExfilBucket() string {
	return getDeployedBucketByType("exfil")
}

// GetCodeBucket returns the name of the first deployed code bucket, or empty
// string if none exists. Used by modules to find the attacker code hosting bucket.
func GetCodeBucket() string {
	return getDeployedBucketByType("code")
}

func getDeployedBucketByType(bucketType string) string {
	name, _ := getDeployedBucketInfo(bucketType)
	return name
}

// GetCodeBucketInfo returns the name and region of the deployed code bucket.
func GetCodeBucketInfo() (name string, region string) {
	return getDeployedBucketInfo("code")
}

// GetExfilBucketInfo returns the name and region of the deployed exfil bucket.
func GetExfilBucketInfo() (name string, region string) {
	return getDeployedBucketInfo("exfil")
}

func getDeployedBucketInfo(bucketType string) (string, string) {
	state, err := LoadDeployState()
	if err != nil {
		return "", ""
	}
	for _, b := range state.Buckets {
		if b.Type == bucketType {
			return b.Name, b.Region
		}
	}
	return "", ""
}

// HasDeployedBuckets returns true if any buckets are tracked in deploy state.
func HasDeployedBuckets() bool {
	state, err := LoadDeployState()
	if err != nil {
		return false
	}
	return len(state.Buckets) > 0
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
