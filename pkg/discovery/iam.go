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

// DiscoverIAMUsers lists IAM users with enriched metadata (attached policies,
// access key count, login profile status). Useful for modules targeting specific users.
func DiscoverIAMUsers(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	iamClient := iam.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allUsers []iamtypes.User
	paginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("TARGET_USER", "iam:ListUsers", err))
			}
			return nil, fmt.Errorf("failed to list users: %v", err)
		}
		allUsers = append(allUsers, page.Users...)
	}

	var choices []modules.DiscoveryChoice
	for _, user := range allUsers {
		userName := aws.ToString(user.UserName)
		metadata := map[string]string{
			"user_name": userName,
		}

		var labelParts []string

		// Enrich with attached policies (best effort)
		policies, err := listAttachedUserPolicies(ctx, iamClient, userName)
		if err == nil && len(policies) > 0 {
			hasAdmin := false
			for _, p := range policies {
				if strings.Contains(p, "AdministratorAccess") {
					hasAdmin = true
					break
				}
			}
			if hasAdmin {
				labelParts = append(labelParts, "[ADMIN]")
			}
			labelParts = append(labelParts, "("+strings.Join(policies, ", ")+")")
			metadata["admin_access"] = fmt.Sprintf("%t", hasAdmin)
		}

		// Enrich with access key count (best effort)
		keyCount, keyErr := countAccessKeys(ctx, iamClient, userName)
		if keyErr == nil {
			metadata["access_key_count"] = fmt.Sprintf("%d", keyCount)
			labelParts = append(labelParts, fmt.Sprintf("[%d keys]", keyCount))
		}

		// Check login profile status (best effort)
		hasLogin, loginErr := hasLoginProfile(ctx, iamClient, userName)
		if loginErr == nil {
			metadata["has_login_profile"] = fmt.Sprintf("%t", hasLogin)
			if hasLogin {
				labelParts = append(labelParts, "[has console]")
			}
		}

		label := userName
		if len(labelParts) > 0 {
			label += " " + strings.Join(labelParts, " ")
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value:    userName,
			Label:    label,
			Metadata: metadata,
		})
	}

	if len(choices) == 0 {
		return nil, fmt.Errorf("no IAM users found in the account")
	}

	return choices, nil
}

// listAttachedUserPolicies returns the names of managed policies attached to a user.
func listAttachedUserPolicies(ctx context.Context, client *iam.Client, userName string) ([]string, error) {
	policyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := client.ListAttachedUserPolicies(policyCtx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(userName),
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

// countAccessKeys returns the number of access keys for a user.
func countAccessKeys(ctx context.Context, client *iam.Client, userName string) (int, error) {
	keyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := client.ListAccessKeys(keyCtx, &iam.ListAccessKeysInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return 0, err
	}
	return len(result.AccessKeyMetadata), nil
}

// hasLoginProfile checks whether a user has a console login profile.
func hasLoginProfile(ctx context.Context, client *iam.Client, userName string) (bool, error) {
	profileCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := client.GetLoginProfile(profileCtx, &iam.GetLoginProfileInput{
		UserName: aws.String(userName),
	})
	if err == nil {
		return true, nil
	}
	if strings.Contains(err.Error(), "NoSuchEntity") {
		return false, nil
	}
	// Other errors (AccessDenied, etc.) — can't determine
	return false, err
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

// DiscoverCallerPolicies lists customer-managed IAM policies attached to the
// current caller (user or role). Useful for modules like iam:CreatePolicyVersion
// that need to target a specific policy ARN.
func DiscoverCallerPolicies(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	stsClient := sts.NewFromConfig(config)
	identityCtx, identityCancel := context.WithTimeout(ctx, 15*time.Second)
	defer identityCancel()

	callerIdentity, err := stsClient.GetCallerIdentity(identityCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("POLICY_ARN", "sts:GetCallerIdentity", err))
		}
		return nil, fmt.Errorf("failed to get caller identity: %v", err)
	}

	callerArn := aws.ToString(callerIdentity.Arn)
	callerAccount := aws.ToString(callerIdentity.Account)
	iamClient := iam.NewFromConfig(config)

	var attachedPolicies []iamtypes.AttachedPolicy

	// Determine caller type from ARN and list attached policies
	if strings.Contains(callerArn, ":user/") {
		// IAM user — extract username from ARN (handles paths like user/path/name)
		parts := strings.SplitN(callerArn, ":user/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("could not parse username from ARN: %s", callerArn)
		}
		// Username is the last segment after any path
		pathParts := strings.Split(parts[1], "/")
		userName := pathParts[len(pathParts)-1]

		fmt.Printf("Discovering policies attached to user: %s\n", userName)

		listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		paginator := iam.NewListAttachedUserPoliciesPaginator(iamClient, &iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(userName),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(listCtx)
			if err != nil {
				if IsAccessDenied(err) {
					return nil, fmt.Errorf("%s", FormatPermissionError("POLICY_ARN", "iam:ListAttachedUserPolicies", err))
				}
				return nil, fmt.Errorf("failed to list attached user policies: %v", err)
			}
			attachedPolicies = append(attachedPolicies, page.AttachedPolicies...)
		}

		// Also check group policies
		groupPolicies, groupErr := listUserGroupPolicies(ctx, iamClient, userName)
		if groupErr == nil {
			attachedPolicies = append(attachedPolicies, groupPolicies...)
		}

	} else if strings.Contains(callerArn, ":assumed-role/") || strings.Contains(callerArn, ":role/") {
		// IAM role — extract role name
		var roleName string
		if strings.Contains(callerArn, ":assumed-role/") {
			// arn:aws:sts::ACCT:assumed-role/RoleName/SessionName
			parts := strings.SplitN(callerArn, ":assumed-role/", 2)
			if len(parts) == 2 {
				roleName = strings.SplitN(parts[1], "/", 2)[0]
			}
		} else {
			// arn:aws:iam::ACCT:role/RoleName
			parts := strings.SplitN(callerArn, ":role/", 2)
			if len(parts) == 2 {
				pathParts := strings.Split(parts[1], "/")
				roleName = pathParts[len(pathParts)-1]
			}
		}

		if roleName == "" {
			return nil, fmt.Errorf("could not parse role name from ARN: %s", callerArn)
		}

		fmt.Printf("Discovering policies attached to role: %s\n", roleName)

		listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		paginator := iam.NewListAttachedRolePoliciesPaginator(iamClient, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(roleName),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(listCtx)
			if err != nil {
				if IsAccessDenied(err) {
					return nil, fmt.Errorf("%s", FormatPermissionError("POLICY_ARN", "iam:ListAttachedRolePolicies", err))
				}
				return nil, fmt.Errorf("failed to list attached role policies: %v", err)
			}
			attachedPolicies = append(attachedPolicies, page.AttachedPolicies...)
		}
	} else {
		return nil, fmt.Errorf("unsupported caller type in ARN: %s", callerArn)
	}

	// Filter to customer-managed policies only (CreatePolicyVersion doesn't work on AWS-managed)
	awsManagedPrefix := "arn:aws:iam::aws:policy/"
	seen := make(map[string]bool)
	var choices []modules.DiscoveryChoice

	for _, p := range attachedPolicies {
		policyArn := aws.ToString(p.PolicyArn)
		policyName := aws.ToString(p.PolicyName)

		// Skip AWS-managed policies
		if strings.HasPrefix(policyArn, awsManagedPrefix) {
			continue
		}

		// Deduplicate (policy could appear via both direct attachment and group)
		if seen[policyArn] {
			continue
		}
		seen[policyArn] = true

		// Verify it belongs to the same account
		expectedPrefix := fmt.Sprintf("arn:aws:iam::%s:policy/", callerAccount)
		if !strings.HasPrefix(policyArn, expectedPrefix) {
			continue
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: policyArn,
			Label: policyName,
			Metadata: map[string]string{
				"policy_name": policyName,
			},
		})
	}

	if len(choices) == 0 {
		return nil, fmt.Errorf("no customer-managed policies found attached to %s (AWS-managed policies cannot be modified with CreatePolicyVersion)", callerArn)
	}

	return choices, nil
}

// listUserGroupPolicies returns managed policies attached via the user's groups.
func listUserGroupPolicies(ctx context.Context, client *iam.Client, userName string) ([]iamtypes.AttachedPolicy, error) {
	groupCtx, groupCancel := context.WithTimeout(ctx, 15*time.Second)
	defer groupCancel()

	groupResult, err := client.ListGroupsForUser(groupCtx, &iam.ListGroupsForUserInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return nil, err
	}

	var policies []iamtypes.AttachedPolicy
	for _, group := range groupResult.Groups {
		policyCtx, policyCancel := context.WithTimeout(ctx, 10*time.Second)
		result, err := client.ListAttachedGroupPolicies(policyCtx, &iam.ListAttachedGroupPoliciesInput{
			GroupName: group.GroupName,
		})
		policyCancel()
		if err != nil {
			continue // best effort
		}
		policies = append(policies, result.AttachedPolicies...)
	}

	return policies, nil
}

// DiscoverCallerGroups lists IAM groups that the calling user belongs to.
// Useful for self-escalation modules targeting group policies (iam-010, iam-011).
func DiscoverCallerGroups(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	// Get caller identity to determine username
	stsClient := sts.NewFromConfig(config)
	identityCtx, identityCancel := context.WithTimeout(ctx, 15*time.Second)
	defer identityCancel()

	callerIdentity, err := stsClient.GetCallerIdentity(identityCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("GROUP_NAME", "sts:GetCallerIdentity", err))
		}
		return nil, fmt.Errorf("failed to get caller identity: %v", err)
	}

	callerArn := aws.ToString(callerIdentity.Arn)

	// Extract username from ARN
	if !strings.Contains(callerArn, ":user/") {
		return nil, fmt.Errorf("caller is not an IAM user (ARN: %s); group discovery requires a user identity", callerArn)
	}
	parts := strings.SplitN(callerArn, ":user/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("could not parse username from ARN: %s", callerArn)
	}
	pathParts := strings.Split(parts[1], "/")
	userName := pathParts[len(pathParts)-1]

	fmt.Printf("Discovering groups for user: %s\n", userName)

	iamClient := iam.NewFromConfig(config)
	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := iamClient.ListGroupsForUser(listCtx, &iam.ListGroupsForUserInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("GROUP_NAME", "iam:ListGroupsForUser", err))
		}
		return nil, fmt.Errorf("failed to list groups for user %s: %v", userName, err)
	}

	var choices []modules.DiscoveryChoice
	for _, group := range result.Groups {
		groupName := aws.ToString(group.GroupName)

		// Enrich with attached policies (best effort)
		var labelParts []string
		policies, pErr := listAttachedGroupPolicies(ctx, iamClient, groupName)
		if pErr == nil && len(policies) > 0 {
			hasAdmin := false
			for _, p := range policies {
				if strings.Contains(p, "AdministratorAccess") {
					hasAdmin = true
					break
				}
			}
			if hasAdmin {
				labelParts = append(labelParts, "[ADMIN]")
			}
			labelParts = append(labelParts, "("+strings.Join(policies, ", ")+")")
		}

		label := groupName
		if len(labelParts) > 0 {
			label += " " + strings.Join(labelParts, " ")
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: groupName,
			Label: label,
			Metadata: map[string]string{
				"group_name": groupName,
				"group_arn":  aws.ToString(group.Arn),
			},
		})
	}

	if len(choices) == 0 {
		return nil, fmt.Errorf("user %s does not belong to any IAM groups", userName)
	}

	return choices, nil
}

// DiscoverIAMGroups lists all IAM groups with enriched metadata (attached policies).
// Useful for modules like iam:AddUserToGroup that need to find privileged groups.
func DiscoverIAMGroups(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	iamClient := iam.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allGroups []iamtypes.Group
	paginator := iam.NewListGroupsPaginator(iamClient, &iam.ListGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("GROUP_NAME", "iam:ListGroups", err))
			}
			return nil, fmt.Errorf("failed to list groups: %v", err)
		}
		allGroups = append(allGroups, page.Groups...)
	}

	var choices []modules.DiscoveryChoice
	for _, group := range allGroups {
		groupName := aws.ToString(group.GroupName)

		var labelParts []string
		hasAdmin := false

		// Enrich with attached policies (best effort)
		policies, pErr := listAttachedGroupPolicies(ctx, iamClient, groupName)
		if pErr == nil && len(policies) > 0 {
			for _, p := range policies {
				if strings.Contains(p, "AdministratorAccess") {
					hasAdmin = true
					break
				}
			}
			if hasAdmin {
				labelParts = append(labelParts, "[ADMIN]")
			}
			labelParts = append(labelParts, "("+strings.Join(policies, ", ")+")")
		}

		label := groupName
		if len(labelParts) > 0 {
			label += " " + strings.Join(labelParts, " ")
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: groupName,
			Label: label,
			Metadata: map[string]string{
				"group_name":   groupName,
				"admin_access": fmt.Sprintf("%t", hasAdmin),
			},
		})
	}

	if len(choices) == 0 {
		return nil, fmt.Errorf("no IAM groups found in the account")
	}

	return choices, nil
}

// DiscoverIAMRoles lists all IAM roles with enriched metadata.
// Unlike DiscoverAssumableRoles, this does not filter by trust policy.
// Useful for modules that modify trust policies (iam-012, iam-019, iam-020, iam-021).
func DiscoverIAMRoles(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	iamClient := iam.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allRoles []iamtypes.Role
	paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("TARGET_ROLE", "iam:ListRoles", err))
			}
			return nil, fmt.Errorf("failed to list roles: %v", err)
		}
		allRoles = append(allRoles, page.Roles...)
	}

	var choices []modules.DiscoveryChoice
	for _, role := range allRoles {
		roleName := aws.ToString(role.RoleName)

		// Skip service-linked roles (can't be modified)
		if strings.HasPrefix(aws.ToString(role.Path), "/aws-service-role/") {
			continue
		}

		var labelParts []string
		hasAdmin := false

		// Enrich with attached policies (best effort)
		policies, pErr := listAttachedPolicies(ctx, iamClient, roleName)
		if pErr == nil && len(policies) > 0 {
			for _, p := range policies {
				if strings.Contains(p, "AdministratorAccess") {
					hasAdmin = true
					break
				}
			}
			if hasAdmin {
				labelParts = append(labelParts, "[ADMIN]")
			}
			labelParts = append(labelParts, "("+strings.Join(policies, ", ")+")")
		}

		label := roleName
		if len(labelParts) > 0 {
			label += " " + strings.Join(labelParts, " ")
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: roleName,
			Label: label,
			Metadata: map[string]string{
				"role_name":    roleName,
				"role_arn":     aws.ToString(role.Arn),
				"admin_access": fmt.Sprintf("%t", hasAdmin),
			},
		})
	}

	if len(choices) == 0 {
		return nil, fmt.Errorf("no IAM roles found in the account")
	}

	return choices, nil
}

// listAttachedGroupPolicies returns the names of managed policies attached to a group.
func listAttachedGroupPolicies(ctx context.Context, client *iam.Client, groupName string) ([]string, error) {
	policyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := client.ListAttachedGroupPolicies(policyCtx, &iam.ListAttachedGroupPoliciesInput{
		GroupName: aws.String(groupName),
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
