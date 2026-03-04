package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"pathrunner/pkg/modules"
)

// RoleInfo contains discovered IAM role information.
type RoleInfo struct {
	RoleArn          string
	RoleName         string
	AttachedPolicies []string
	HasAdminAccess   bool
}

// InstanceProfileInfo contains discovered instance profile information.
type InstanceProfileInfo struct {
	Name string
	Arn  string
	// Roles associated with this instance profile
	Roles []RoleInfo
}

// trustPolicyDocument represents an IAM role trust policy.
type trustPolicyDocument struct {
	Statement []trustPolicyStatement `json:"Statement"`
}

type trustPolicyStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    any             `json:"Action"`
}

// DiscoverRolesForService lists IAM roles whose trust policy allows
// the given service principal (e.g., "lambda.amazonaws.com").
// Enriches with attached policy names when possible.
func DiscoverRolesForService(ctx context.Context, config aws.Config, servicePrincipal string) ([]modules.DiscoveryChoice, error) {
	client := iam.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allRoles []iamtypes.Role
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("ROLE_ARN", "iam:ListRoles", err))
			}
			return nil, fmt.Errorf("failed to list roles: %v", err)
		}
		allRoles = append(allRoles, page.Roles...)
	}

	// Filter roles by trust policy
	var matchingRoles []RoleInfo
	for _, role := range allRoles {
		if role.AssumeRolePolicyDocument == nil {
			continue
		}

		// Trust policy is URL-encoded
		decoded, err := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))
		if err != nil {
			continue
		}

		if trustsService(decoded, servicePrincipal) {
			info := RoleInfo{
				RoleArn:  aws.ToString(role.Arn),
				RoleName: aws.ToString(role.RoleName),
			}
			matchingRoles = append(matchingRoles, info)
		}
	}

	// Enrich with attached policies (best effort)
	for i := range matchingRoles {
		policies, err := listAttachedPolicies(ctx, client, matchingRoles[i].RoleName)
		if err == nil {
			matchingRoles[i].AttachedPolicies = policies
			for _, p := range policies {
				if strings.Contains(p, "AdministratorAccess") {
					matchingRoles[i].HasAdminAccess = true
					break
				}
			}
		}
	}

	// Convert to DiscoveryChoice
	var choices []modules.DiscoveryChoice
	for _, role := range matchingRoles {
		label := role.RoleName
		if role.HasAdminAccess {
			label += " [ADMIN]"
		}
		if len(role.AttachedPolicies) > 0 {
			label += " (" + strings.Join(role.AttachedPolicies, ", ") + ")"
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: role.RoleArn,
			Label: label,
			Metadata: map[string]string{
				"role_name":    role.RoleName,
				"admin_access": fmt.Sprintf("%t", role.HasAdminAccess),
			},
		})
	}

	return choices, nil
}

// DiscoverInstanceProfiles lists IAM instance profiles and their associated roles.
func DiscoverInstanceProfiles(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := iam.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allProfiles []iamtypes.InstanceProfile
	paginator := iam.NewListInstanceProfilesPaginator(client, &iam.ListInstanceProfilesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("INSTANCE_PROFILE", "iam:ListInstanceProfiles", err))
			}
			return nil, fmt.Errorf("failed to list instance profiles: %v", err)
		}
		allProfiles = append(allProfiles, page.InstanceProfiles...)
	}

	var choices []modules.DiscoveryChoice
	for _, profile := range allProfiles {
		profileName := aws.ToString(profile.InstanceProfileName)
		var roleNames []string
		hasAdmin := false

		for _, role := range profile.Roles {
			roleName := aws.ToString(role.RoleName)
			roleNames = append(roleNames, roleName)

			// Check attached policies for admin access (best effort)
			policies, err := listAttachedPolicies(ctx, client, roleName)
			if err == nil {
				for _, p := range policies {
					if strings.Contains(p, "AdministratorAccess") {
						hasAdmin = true
						break
					}
				}
			}
		}

		label := profileName
		if len(roleNames) > 0 {
			label += " (roles: " + strings.Join(roleNames, ", ") + ")"
		}
		if hasAdmin {
			label += " [ADMIN]"
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: profileName,
			Label: label,
			Metadata: map[string]string{
				"arn":          aws.ToString(profile.Arn),
				"roles":        strings.Join(roleNames, ","),
				"admin_access": fmt.Sprintf("%t", hasAdmin),
			},
		})
	}

	return choices, nil
}

// trustsService checks if a trust policy document allows the given service principal.
func trustsService(policyDoc string, servicePrincipal string) bool {
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(policyDoc), &doc); err != nil {
		return false
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		// Principal can be a string or an object
		var principalMap map[string]any
		if err := json.Unmarshal(stmt.Principal, &principalMap); err != nil {
			// Try as a plain string (e.g., "*")
			var principalStr string
			if err2 := json.Unmarshal(stmt.Principal, &principalStr); err2 == nil {
				if principalStr == "*" {
					return true
				}
			}
			continue
		}

		// Check Service key
		if svc, ok := principalMap["Service"]; ok {
			switch v := svc.(type) {
			case string:
				if v == servicePrincipal {
					return true
				}
			case []any:
				for _, s := range v {
					if str, ok := s.(string); ok && str == servicePrincipal {
						return true
					}
				}
			}
		}
	}

	return false
}

// DiscoverAssumableRoles lists IAM roles whose trust policy allows the
// current caller to assume them. Calls sts:GetCallerIdentity to determine
// the caller's ARN and account, then filters roles by trust policy.
func DiscoverAssumableRoles(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	// Get caller identity to know who we are
	stsClient := sts.NewFromConfig(config)
	identityCtx, identityCancel := context.WithTimeout(ctx, 15*time.Second)
	defer identityCancel()

	callerIdentity, err := stsClient.GetCallerIdentity(identityCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("ROLE_ARN", "sts:GetCallerIdentity", err))
		}
		return nil, fmt.Errorf("failed to get caller identity: %v", err)
	}

	callerArn := aws.ToString(callerIdentity.Arn)
	callerAccount := aws.ToString(callerIdentity.Account)

	fmt.Printf("Filtering roles assumable by: %s\n", callerArn)

	// List all roles
	iamClient := iam.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allRoles []iamtypes.Role
	paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("ROLE_ARN", "iam:ListRoles", err))
			}
			return nil, fmt.Errorf("failed to list roles: %v", err)
		}
		allRoles = append(allRoles, page.Roles...)
	}

	// Filter roles by trust policy
	var matchingRoles []RoleInfo
	for _, role := range allRoles {
		if role.AssumeRolePolicyDocument == nil {
			continue
		}

		decoded, err := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))
		if err != nil {
			continue
		}

		if trustsAWSPrincipal(decoded, callerArn, callerAccount) {
			info := RoleInfo{
				RoleArn:  aws.ToString(role.Arn),
				RoleName: aws.ToString(role.RoleName),
			}
			matchingRoles = append(matchingRoles, info)
		}
	}

	// Enrich with attached policies (best effort)
	for i := range matchingRoles {
		policies, err := listAttachedPolicies(ctx, iamClient, matchingRoles[i].RoleName)
		if err == nil {
			matchingRoles[i].AttachedPolicies = policies
			for _, p := range policies {
				if strings.Contains(p, "AdministratorAccess") {
					matchingRoles[i].HasAdminAccess = true
					break
				}
			}
		}
	}

	// Convert to DiscoveryChoice
	var choices []modules.DiscoveryChoice
	for _, role := range matchingRoles {
		label := role.RoleName
		if role.HasAdminAccess {
			label += " [ADMIN]"
		}
		if len(role.AttachedPolicies) > 0 {
			label += " (" + strings.Join(role.AttachedPolicies, ", ") + ")"
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: role.RoleArn,
			Label: label,
			Metadata: map[string]string{
				"role_name":    role.RoleName,
				"admin_access": fmt.Sprintf("%t", role.HasAdminAccess),
			},
		})
	}

	return choices, nil
}

// trustsAWSPrincipal checks if a trust policy document allows the given
// AWS principal (by exact ARN, account root, or wildcard).
// callerArn is the full ARN from sts:GetCallerIdentity.
// callerAccount is the 12-digit account ID.
func trustsAWSPrincipal(policyDoc string, callerArn string, callerAccount string) bool {
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(policyDoc), &doc); err != nil {
		return false
	}

	// Normalize assumed-role ARNs to the underlying role ARN for matching.
	// sts:GetCallerIdentity returns "arn:aws:sts::ACCT:assumed-role/RoleName/Session"
	// but trust policies reference "arn:aws:iam::ACCT:role/RoleName".
	normalizedArn := normalizeCallerArn(callerArn, callerAccount)

	accountRoot := fmt.Sprintf("arn:aws:iam::%s:root", callerAccount)

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		// Check that the statement allows sts:AssumeRole
		if !actionAllowsAssumeRole(stmt.Action) {
			continue
		}

		// Principal can be a string or an object
		var principalMap map[string]any
		if err := json.Unmarshal(stmt.Principal, &principalMap); err != nil {
			// Try as a plain string (e.g., "*")
			var principalStr string
			if err2 := json.Unmarshal(stmt.Principal, &principalStr); err2 == nil {
				if principalStr == "*" {
					return true
				}
			}
			continue
		}

		// Check AWS key
		if awsPrincipal, ok := principalMap["AWS"]; ok {
			if matchesPrincipal(awsPrincipal, callerArn, normalizedArn, accountRoot) {
				return true
			}
		}
	}

	return false
}

// normalizeCallerArn converts assumed-role ARNs to the underlying role ARN.
// "arn:aws:sts::123456789012:assumed-role/MyRole/session" becomes
// "arn:aws:iam::123456789012:role/MyRole"
func normalizeCallerArn(callerArn string, callerAccount string) string {
	// Check for assumed-role pattern
	prefix := fmt.Sprintf("arn:aws:sts::%s:assumed-role/", callerAccount)
	if strings.HasPrefix(callerArn, prefix) {
		remainder := strings.TrimPrefix(callerArn, prefix)
		// remainder is "RoleName/SessionName"
		parts := strings.SplitN(remainder, "/", 2)
		if len(parts) >= 1 {
			return fmt.Sprintf("arn:aws:iam::%s:role/%s", callerAccount, parts[0])
		}
	}
	return callerArn
}

// matchesPrincipal checks if a trust policy principal value matches the caller.
func matchesPrincipal(principal any, callerArn, normalizedArn, accountRoot string) bool {
	switch v := principal.(type) {
	case string:
		return principalMatches(v, callerArn, normalizedArn, accountRoot)
	case []any:
		for _, p := range v {
			if str, ok := p.(string); ok {
				if principalMatches(str, callerArn, normalizedArn, accountRoot) {
					return true
				}
			}
		}
	}
	return false
}

// principalMatches checks a single principal string against the caller identity.
func principalMatches(principal, callerArn, normalizedArn, accountRoot string) bool {
	if principal == "*" {
		return true
	}
	// Account root matches any principal in that account
	if principal == accountRoot {
		return true
	}
	// Exact ARN match (either the raw caller ARN or the normalized role ARN)
	if principal == callerArn || principal == normalizedArn {
		return true
	}
	return false
}

// actionAllowsAssumeRole checks if a trust policy statement's Action includes sts:AssumeRole.
func actionAllowsAssumeRole(action any) bool {
	switch v := action.(type) {
	case string:
		return v == "sts:AssumeRole" || v == "sts:*" || v == "*"
	case []any:
		for _, a := range v {
			if str, ok := a.(string); ok {
				if str == "sts:AssumeRole" || str == "sts:*" || str == "*" {
					return true
				}
			}
		}
		return false
	case nil:
		// If action is missing, be permissive (trust policies almost always have it)
		return true
	default:
		return true
	}
}

// listAttachedPolicies returns the names of policies attached to a role.
func listAttachedPolicies(ctx context.Context, client *iam.Client, roleName string) ([]string, error) {
	policyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := client.ListAttachedRolePolicies(policyCtx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, err
	}

	var names []string
	for _, p := range result.AttachedPolicies {
		names = append(names, aws.ToString(p.PolicyName))
	}
	return names, nil
}
