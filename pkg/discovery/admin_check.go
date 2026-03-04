package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// AdminCheckActions are the IAM actions tested to determine admin access.
// Inspired by CloudFox's approach — if a principal can perform all of these,
// it effectively has admin-level privileges.
var AdminCheckActions = []string{
	"iam:PutUserPolicy",
	"iam:AttachUserPolicy",
	"iam:PutRolePolicy",
	"iam:AttachRolePolicy",
	"secretsmanager:GetSecretValue",
	"ssm:GetParameters",
}

// AdminCheckResult contains the results of an admin privilege check.
type AdminCheckResult struct {
	IsAdmin       bool
	AllowedCount  int
	DeniedCount   int
	DeniedActions []string
}

// NormalizeARNForSimulator converts assumed-role STS ARNs to IAM role ARNs
// that SimulatePrincipalPolicy accepts.
//
// arn:aws:sts::123456789012:assumed-role/MyRole/session-name
// becomes:
// arn:aws:iam::123456789012:role/MyRole
//
// User and role ARNs are returned unchanged.
func NormalizeARNForSimulator(arn string) string {
	// arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME
	if strings.Contains(arn, ":assumed-role/") {
		parts := strings.SplitN(arn, ":", 6) // partition, service, region, account, resource
		if len(parts) == 6 {
			account := parts[4]
			resource := parts[5] // assumed-role/ROLE_NAME/SESSION_NAME
			resourceParts := strings.SplitN(resource, "/", 3)
			if len(resourceParts) >= 2 {
				roleName := resourceParts[1]
				return fmt.Sprintf("arn:%s:iam::%s:role/%s", parts[1], account, roleName)
			}
		}
	}
	return arn
}

// CheckAdminPrivileges uses the IAM Policy Simulator to test whether a principal
// has admin-level access by simulating a set of high-privilege actions.
func CheckAdminPrivileges(ctx context.Context, cfg aws.Config, principalARN string) (*AdminCheckResult, error) {
	// SimulatePrincipalPolicy requires IAM ARNs, not STS assumed-role ARNs
	principalARN = NormalizeARNForSimulator(principalARN)

	client := iam.NewFromConfig(cfg)

	simCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := client.SimulatePrincipalPolicy(simCtx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(principalARN),
		ActionNames:     AdminCheckActions,
		ResourceArns:    []string{"*"},
	})
	if err != nil {
		return nil, fmt.Errorf("SimulatePrincipalPolicy failed: %v", err)
	}

	result := &AdminCheckResult{}
	for _, evalResult := range resp.EvaluationResults {
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
			result.AllowedCount++
		} else {
			result.DeniedCount++
			if evalResult.EvalActionName != nil {
				result.DeniedActions = append(result.DeniedActions, *evalResult.EvalActionName)
			}
		}
	}

	result.IsAdmin = result.DeniedCount == 0 && result.AllowedCount == len(AdminCheckActions)
	return result, nil
}
