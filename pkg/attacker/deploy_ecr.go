// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// DeployECR creates an ECR repository in the attacker account and sets a
// cross-account pull policy for the victim accounts. The repo is generic
// infrastructure -- modules push their own service-specific images into it.
// Returns the repository URI.
func DeployECR(attackerCfg aws.Config, repoName string, victimAccountIDs []string, region string) (string, error) {
	// Create the ECR repository
	fmt.Printf("[*] Creating ECR repository '%s' in %s...\n", repoName, region)
	repoURI, err := CreateECRRepository(attackerCfg, repoName, region)
	if err != nil {
		return "", err
	}
	fmt.Printf("[*] Created ECR repository: %s\n", repoURI)

	// Set cross-account pull policy for victim accounts
	if len(victimAccountIDs) > 0 {
		fmt.Printf("[*] Setting cross-account pull policy for %d victim account(s)...\n", len(victimAccountIDs))
		if err := SetECRPullPolicy(attackerCfg, repoName, victimAccountIDs, region); err != nil {
			return "", fmt.Errorf("ECR repo created but failed to set pull policy: %v", err)
		}
	}

	// Track in deploy state
	state, err := LoadDeployState()
	if err != nil {
		return repoURI, fmt.Errorf("ECR repo created (%s) but failed to load deploy state: %v", repoURI, err)
	}

	state.ECRRepos = append(state.ECRRepos, ECRRepoDeployState{
		RepositoryName: repoName,
		RepositoryURI:  repoURI,
		Region:         region,
		AccountIDs:     victimAccountIDs,
	})

	if err := SaveDeployState(state); err != nil {
		return repoURI, fmt.Errorf("ECR repo created (%s) but failed to save deploy state: %v", repoURI, err)
	}

	return repoURI, nil
}

// EnsureECRAccountAccess checks if the given account ID already has pull access
// to all deployed ECR repos. If not, updates repo policies and deploy state.
// Returns the number of repos updated.
func EnsureECRAccountAccess(attackerCfg aws.Config, newAccountID string) (int, error) {
	state, err := LoadDeployState()
	if err != nil {
		return 0, err
	}

	if len(state.ECRRepos) == 0 {
		return 0, nil
	}

	updated := 0
	for i := range state.ECRRepos {
		repo := &state.ECRRepos[i]

		// Check if this account already has access
		hasAccess := false
		for _, existingID := range repo.AccountIDs {
			if existingID == newAccountID {
				hasAccess = true
				break
			}
		}
		if hasAccess {
			continue
		}

		// Add the new account ID and update the policy
		repo.AccountIDs = append(repo.AccountIDs, newAccountID)
		if err := SetECRPullPolicy(attackerCfg, repo.RepositoryName, repo.AccountIDs, repo.Region); err != nil {
			return updated, fmt.Errorf("failed to update policy for ECR repo '%s': %v", repo.RepositoryName, err)
		}
		updated++
	}

	if updated > 0 {
		if err := SaveDeployState(state); err != nil {
			return updated, fmt.Errorf("ECR policies updated but failed to save deploy state: %v", err)
		}
	}

	return updated, nil
}

// GetECRRepoURI returns the repository URI of the first deployed ECR repo,
// or empty string if none exists. Modules append their own image tag to build
// the full CONTAINER_URI.
func GetECRRepoURI() string {
	state, err := LoadDeployState()
	if err != nil {
		return ""
	}
	if len(state.ECRRepos) == 0 {
		return ""
	}
	return state.ECRRepos[0].RepositoryURI
}

// HasDeployedECRRepos returns true if any ECR repos are tracked in deploy state.
func HasDeployedECRRepos() bool {
	state, err := LoadDeployState()
	if err != nil {
		return false
	}
	return len(state.ECRRepos) > 0
}

// DestroyECRRepo deletes a specific ECR repository and removes it from deploy state.
func DestroyECRRepo(attackerCfg aws.Config, repoName string) error {
	state, err := LoadDeployState()
	if err != nil {
		return err
	}

	var targetRepo *ECRRepoDeployState
	var targetIndex int
	for i, r := range state.ECRRepos {
		if r.RepositoryName == repoName {
			targetRepo = &state.ECRRepos[i]
			targetIndex = i
			break
		}
	}

	if targetRepo == nil {
		return fmt.Errorf("ECR repo '%s' not found in deploy state", repoName)
	}

	if err := DeleteECRRepository(attackerCfg, repoName, targetRepo.Region); err != nil {
		return err
	}

	state.ECRRepos = append(state.ECRRepos[:targetIndex], state.ECRRepos[targetIndex+1:]...)

	if state.HasAnyDeployedResources() {
		return SaveDeployState(state)
	}
	return RemoveDeployState()
}

// DestroyAllECRRepos deletes all tracked ECR repositories.
func DestroyAllECRRepos(attackerCfg aws.Config) error {
	state, err := LoadDeployState()
	if err != nil {
		return err
	}

	if len(state.ECRRepos) == 0 {
		return fmt.Errorf("no tracked ECR repos to destroy")
	}

	var lastErr error
	for _, r := range state.ECRRepos {
		fmt.Printf("[*] Deleting ECR repo %s...\n", r.RepositoryName)
		if err := DeleteECRRepository(attackerCfg, r.RepositoryName, r.Region); err != nil {
			fmt.Printf("[!] Failed to delete %s: %v\n", r.RepositoryName, err)
			lastErr = err
		}
	}

	state.ECRRepos = nil
	if state.HasAnyDeployedResources() {
		SaveDeployState(state)
	} else {
		RemoveDeployState()
	}

	return lastErr
}

// ListDeployedECRRepos returns all tracked ECR repos from deploy state.
func ListDeployedECRRepos() ([]ECRRepoDeployState, error) {
	state, err := LoadDeployState()
	if err != nil {
		return nil, err
	}
	return state.ECRRepos, nil
}
