package repl

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/ui"
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
		return r.attackerIdentityShow()
	}

	switch args[0] {
	case "identity":
		return r.attackerIdentity(args[1:])
	// Legacy aliases — keep old commands working
	case "set":
		return r.attackerSet(args[1:])
	case "show":
		return r.attackerIdentityShow()
	case "clear":
		return r.attackerIdentityRemove()
	case "validate":
		return r.attackerIdentityValidate()
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

// attackerIdentity routes attacker identity subcommands
func (r *REPL) attackerIdentity(args []string) error {
	if len(args) == 0 {
		return r.attackerIdentityShow()
	}

	switch args[0] {
	case "show":
		return r.attackerIdentityShow()
	case "add":
		return r.attackerIdentityAdd(args[1:])
	case "remove":
		return r.attackerIdentityRemove()
	case "validate":
		return r.attackerIdentityValidate()
	case "help":
		return r.showAttackerIdentityHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown attacker identity subcommand: %s. Use 'attacker identity help' for available commands", args[0]))
	}
}

// attackerIdentityAdd configures the attacker identity from a profile or access keys
func (r *REPL) attackerIdentityAdd(args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("attacker identity add requires a credential source. Use 'attacker identity help' for usage")
	}

	if args[0] == "help" {
		return r.showAttackerIdentityAddHelp()
	}

	switch args[0] {
	case "profile":
		if len(args) < 2 {
			return NewInvalidArgumentsError("attacker identity add profile requires a profile name")
		}
		return r.attackerSetProfile(args[1])
	case "keys":
		return r.attackerSetKeys(args[1:])
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown credential source: %s. Use 'profile' or 'keys'", args[0]))
	}
}

// attackerSet is a legacy alias for attackerIdentityAdd
func (r *REPL) attackerSet(args []string) error {
	if len(args) == 0 {
		return NewInvalidArgumentsError("attacker set requires a credential source. Use 'attacker identity help' for usage")
	}

	if args[0] == "help" {
		return r.showAttackerIdentityAddHelp()
	}

	return r.attackerIdentityAdd(args)
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

// attackerIdentityShow displays the current attacker identity
func (r *REPL) attackerIdentityShow() error {
	identity := r.identityManager.GetAttackerIdentity()
	if identity == nil {
		fmt.Println("No attacker identity configured.")
		fmt.Println("Use 'attacker identity add profile <name>' or 'attacker identity add keys ...' to configure one.")
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

// attackerIdentityRemove removes the attacker identity
func (r *REPL) attackerIdentityRemove() error {
	if r.identityManager.GetAttackerIdentity() == nil {
		fmt.Println("No attacker identity configured.")
		return nil
	}
	r.identityManager.ClearAttackerIdentity()
	fmt.Println("Attacker identity removed.")
	return nil
}

// attackerIdentityValidate validates the attacker identity credentials
func (r *REPL) attackerIdentityValidate() error {
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
	fmt.Println("Attacker Commands:")
	fmt.Println()
	fmt.Println("Identity:")
	fmt.Println("  attacker identity show                                   - Show current attacker identity")
	fmt.Println("  attacker identity add profile <name>                     - Configure from AWS profile")
	fmt.Println("  attacker identity add keys --access <key> --secret <secret> [--token <token>] [--region <region>]")
	fmt.Println("                                                           - Configure from access keys")
	fmt.Println("  attacker identity remove                                 - Remove attacker identity")
	fmt.Println("  attacker identity validate                               - Validate attacker credentials")
	fmt.Println()
	fmt.Println("Listener:")
	fmt.Println("  attacker listener start [flags]                          - Start credential collector + shell listener")
	fmt.Println("  attacker listener stop                                   - Stop the listener")
	fmt.Println("  attacker listener status                                 - Show listener state and stats")
	fmt.Println()
	fmt.Println("Infrastructure:")
	fmt.Println("  attacker infra ec2 [create] [--region <region>]          - Deploy pathrunner to EC2")
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
	fmt.Println("  attacker show                                            - Shortcut for 'attacker identity show'")
	fmt.Println("  attacker set ...                                         - Shortcut for 'attacker identity add ...'")
	fmt.Println("  attacker clear                                           - Shortcut for 'attacker identity remove'")
	fmt.Println("  attacker validate                                        - Shortcut for 'attacker identity validate'")
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

func (r *REPL) showAttackerIdentityHelp() error {
	fmt.Println("Attacker Identity Commands:")
	fmt.Println("  attacker identity show                                   - Show current attacker identity")
	fmt.Println("  attacker identity add profile <name>                     - Configure from AWS profile (SSO supported)")
	fmt.Println("  attacker identity add keys --access <key> --secret <secret> [--token <token>] [--region <region>]")
	fmt.Println("                                                           - Configure from static access keys")
	fmt.Println("  attacker identity remove                                 - Remove attacker identity")
	fmt.Println("  attacker identity validate                               - Validate attacker credentials")
	fmt.Println()
	fmt.Println("The attacker identity is a single credential used for deploying attacker-side")
	fmt.Println("infrastructure (EC2 instances, S3 buckets, ECR repos). It is separate from the")
	fmt.Println("switchable victim identities managed by the 'identity' command.")
	return nil
}

func (r *REPL) showAttackerIdentityAddHelp() error {
	fmt.Println("Attacker Identity Add:")
	fmt.Println("  attacker identity add profile <name>                     - Configure from AWS profile (SSO supported)")
	fmt.Println("  attacker identity add keys --access <key> --secret <secret> [--token <token>] [--region <region>]")
	fmt.Println("                                                           - Configure from static access keys")
	fmt.Println()
	fmt.Println("Adding replaces any existing attacker identity.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  attacker identity add profile attacker-account")
	fmt.Println("  attacker identity add keys --access AKIAEXAMPLE --secret wJalrXUtnFEMI --region us-west-2")
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
