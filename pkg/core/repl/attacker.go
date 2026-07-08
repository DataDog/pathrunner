package repl

import (
	"context"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/ui"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// cmdAttacker manages the attacker account identity
func (r *REPL) cmdAttacker(repl *REPL, args []string) error {
	if len(args) == 0 {
		return r.attackerShow()
	}

	switch args[0] {
	case "set":
		return r.attackerSet(args[1:])
	case "show":
		return r.attackerShow()
	case "clear":
		return r.attackerClear()
	case "validate":
		return r.attackerValidate()
	case "listener":
		return r.cmdAttackerListener(args[1:])
	case "infra":
		return r.cmdAttackerDeploy(args[1:])
	case "help":
		return r.showAttackerHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown attacker subcommand: %s. Use 'attacker help' for available commands", args[0]))
	}
}

// attackerSet configures the attacker identity from a profile or access keys
func (r *REPL) attackerSet(args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("attacker set requires a credential source. Use 'attacker help' for usage")
	}

	if args[0] == "help" {
		return r.showAttackerSetHelp()
	}

	switch args[0] {
	case "profile":
		if len(args) < 2 {
			return NewInvalidArgumentsError("attacker set profile requires a profile name")
		}
		return r.attackerSetProfile(args[1])
	case "keys":
		return r.attackerSetKeys(args[1:])
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown attacker set source: %s. Use 'profile' or 'keys'", args[0]))
	}
}

func (r *REPL) attackerSetProfile(profileName string) error {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithSharedConfigProfile(profileName))
	if err != nil {
		return fmt.Errorf("failed to load AWS profile '%s': %v", profileName, err)
	}

	region := cfg.Region
	if region == "" {
		region = "us-east-1"
		fmt.Println("Profile does not specify a region, using default: us-east-1")
	}

	identity := &modules.Identity{
		Name:    fmt.Sprintf("attacker/%s", profileName),
		Type:    "profile",
		Profile: profileName,
		Region:  region,
	}
	identity.SetConfig(cfg)

	if err := identity.Validate(); err != nil {
		return fmt.Errorf("attacker profile credentials validation failed: %v", err)
	}

	r.identityManager.SetAttackerIdentity(identity)
	fmt.Printf("Attacker account configured from profile '%s'\n", profileName)
	fmt.Printf("ARN: %s\n", identity.CallerARN)
	return nil
}

func (r *REPL) attackerSetKeys(args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("attacker set keys requires --access and --secret flags")
	}

	accessKey := extractFlag(args, "--access")
	secretKey := extractFlag(args, "--secret")
	sessionToken := extractFlag(args, "--token")
	region := extractFlag(args, "--region")

	if accessKey == "" || secretKey == "" {
		return NewInvalidArgumentsError("--access and --secret are required for attacker set keys")
	}

	if region == "" {
		region = "us-east-1"
	}

	creds := credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(creds),
		config.WithRegion(region),
	)
	if err != nil {
		return fmt.Errorf("failed to create config from keys: %v", err)
	}

	name := fmt.Sprintf("attacker/keys_%s", accessKey[len(accessKey)-4:])
	identity := &modules.Identity{
		Name:         name,
		Type:         "keys",
		AccessKeyID:  accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Region:       region,
	}
	identity.SetConfig(cfg)

	if sessionToken != "" {
		expiresAt := time.Now().Add(1 * time.Hour)
		identity.ExpiresAt = &expiresAt
	}

	if err := identity.Validate(); err != nil {
		return fmt.Errorf("attacker key credentials validation failed: %v", err)
	}

	r.identityManager.SetAttackerIdentity(identity)
	fmt.Printf("Attacker account configured from access keys\n")
	fmt.Printf("ARN: %s\n", identity.CallerARN)
	return nil
}

// attackerShow displays the current attacker identity
func (r *REPL) attackerShow() error {
	identity := r.identityManager.GetAttackerIdentity()
	if identity == nil {
		fmt.Println("No attacker account configured.")
		fmt.Println("Use 'attacker set profile <name>' or 'attacker set keys ...' to configure one.")
		return nil
	}

	kvPairs := []ui.KV{
		{Key: "Name", Value: identity.Name},
		{Key: "Type", Value: identity.Type},
		{Key: "Region", Value: identity.Region},
	}

	if identity.Profile != "" {
		kvPairs = append(kvPairs, ui.KV{Key: "Profile", Value: identity.Profile})
	}
	if identity.CallerARN != "" {
		kvPairs = append(kvPairs, ui.KV{Key: "ARN", Value: identity.CallerARN})
	}

	if identity.ExpiresAt != nil {
		kvPairs = append(kvPairs, ui.KV{Key: "Expires", Value: identity.ExpiresAt.Format("2006-01-02 15:04:05 MST")})
		if identity.IsExpired() {
			kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: "EXPIRED"})
		} else {
			kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: "Valid"})
		}
	} else {
		kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: "Valid (no expiration)"})
	}

	fmt.Println("Attacker Account:")
	fmt.Println()
	ui.KeyValueTable("", kvPairs)
	fmt.Println()
	return nil
}

// attackerClear removes the attacker identity
func (r *REPL) attackerClear() error {
	if r.identityManager.GetAttackerIdentity() == nil {
		fmt.Println("No attacker account configured.")
		return nil
	}
	r.identityManager.ClearAttackerIdentity()
	fmt.Println("Attacker account cleared.")
	return nil
}

// attackerValidate validates the attacker identity credentials
func (r *REPL) attackerValidate() error {
	identity := r.identityManager.GetAttackerIdentity()
	if identity == nil {
		return fmt.Errorf("no attacker account configured")
	}

	if identity.IsExpired() {
		return fmt.Errorf("attacker credentials have expired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stsClient := sts.NewFromConfig(identity.GetConfig())
	result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("attacker credential validation failed: %v", err)
	}

	identity.CallerARN = aws.ToString(result.Arn)
	fmt.Printf("Attacker credentials valid.\n")
	fmt.Printf("ARN: %s\n", identity.CallerARN)
	fmt.Printf("Account: %s\n", aws.ToString(result.Account))
	return nil
}

func (r *REPL) showAttackerHelp() error {
	fmt.Println("Attacker Account Commands:")
	fmt.Println("  attacker set profile <name>                              - Configure from AWS profile")
	fmt.Println("  attacker set keys --access <key> --secret <secret> [--token <token>] [--region <region>]")
	fmt.Println("                                                           - Configure from access keys")
	fmt.Println("  attacker show                                            - Show current attacker identity")
	fmt.Println("  attacker validate                                        - Validate attacker credentials")
	fmt.Println("  attacker clear                                           - Remove attacker identity")
	fmt.Println()
	fmt.Println("  attacker listener start [flags]                          - Start credential collector + shell listener")
	fmt.Println("  attacker listener stop                                   - Stop the listener")
	fmt.Println("  attacker listener status                                 - Show listener state and stats")
	fmt.Println()
	fmt.Println("  attacker infra ec2 [create] [--region <region>]           - Deploy pathrunner to EC2")
	fmt.Println("  attacker infra ec2 update                                - Update binary on existing EC2 instance")
	fmt.Println("  attacker infra ec2 status                                - Show EC2 instance state")
	fmt.Println("  attacker infra ec2 destroy                               - Tear down EC2 deployment")
	fmt.Println("  attacker infra status                                    - Show all deployed infrastructure")
	fmt.Println("  attacker infra destroy                                   - Tear down ALL deployed infrastructure")
	fmt.Println()
	fmt.Println("  attacker help                                            - Show this help message")
	fmt.Println()
	fmt.Println("Aliases:")
	fmt.Println("  listener                                                 - Shortcut for 'attacker listener'")
	fmt.Println("  infra                                                    - Shortcut for 'attacker infra'")
	fmt.Println()
	fmt.Println("The attacker account is used by modules that need to deploy resources in a")
	fmt.Println("separate AWS account (e.g., S3 buckets for hosting malicious code, ECR repos")
	fmt.Println("for container images). It is NOT part of the switchable identities list.")
	fmt.Println()
	fmt.Println("The listener provides a built-in HTTPS credential collector (POST /collect)")
	fmt.Println("and a TLS reverse shell listener. Starting the listener auto-configures")
	fmt.Println("payload options like HTTPS_URL, LHOST, and LPORT.")
	fmt.Println()
	fmt.Println("The attacker identity persists across sessions within the current workspace.")
	return nil
}

func (r *REPL) showAttackerSetHelp() error {
	fmt.Println("Attacker Set Command:")
	fmt.Println("  attacker set profile <name>                              - Configure from AWS profile (SSO supported)")
	fmt.Println("  attacker set keys --access <key> --secret <secret> [--token <token>] [--region <region>]")
	fmt.Println("                                                           - Configure from static access keys")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  attacker set profile attacker-account")
	fmt.Println("  attacker set keys --access AKIAEXAMPLE --secret wJalrXUtnFEMI --region us-west-2")
	return nil
}

// extractFlag extracts the value for a --flag from args
func extractFlag(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// showAttackerContext returns a short string for the attacker account in context display
func (r *REPL) showAttackerContext() string {
	identity := r.identityManager.GetAttackerIdentity()
	if identity == nil {
		return ""
	}

	// Extract account ID from ARN
	if identity.CallerARN != "" {
		parts := strings.Split(identity.CallerARN, ":")
		if len(parts) >= 5 {
			return parts[4]
		}
	}
	return identity.Name
}
