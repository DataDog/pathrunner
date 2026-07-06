package repl

import (
	"fmt"
	"pathrunner/pkg/attacker"
	"pathrunner/pkg/ui"
	"strings"
)

// cmdAttackerDeploy handles the "attacker infra" subcommand tree.
func (r *REPL) cmdAttackerDeploy(args []string) error {
	if len(args) == 0 {
		return r.showAttackerDeployHelp()
	}

	switch args[0] {
	case "ec2":
		return r.cmdDeployEC2(args[1:])
	case "bucket":
		return r.cmdDeployBucket(args[1:])
	case "status":
		return r.deployGlobalStatus()
	case "destroy":
		return r.deployGlobalDestroy()
	case "help":
		return r.showAttackerDeployHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown infra resource: %s. Use 'attacker infra help' for available resources", args[0]))
	}
}

// --- EC2 subcommands ---

func (r *REPL) cmdDeployEC2(args []string) error {
	if len(args) == 0 {
		// Default action is create
		return r.deployEC2Create(nil)
	}

	switch args[0] {
	case "create":
		return r.deployEC2Create(args[1:])
	case "status":
		return r.deployEC2Status()
	case "destroy":
		return r.deployEC2Destroy()
	case "help":
		return r.showDeployEC2Help()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown deploy ec2 action: %s. Use 'attacker infra ec2 help'", args[0]))
	}
}

func (r *REPL) deployEC2Create(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showDeployEC2Help()
	}

	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required. Use 'attacker set profile <name>' first")
	}

	region := extractFlag(args, "--region")
	if region == "" {
		region = attackerIdentity.Region
	}
	if region == "" {
		region = attackerIdentity.GetConfig().Region
	}
	if region == "" {
		return fmt.Errorf("no region configured. Use --region or set a region on the attacker identity")
	}

	// Detect operator's public IP for SSH security group rule
	operatorIP, err := attacker.DetectPublicIP()
	if err != nil {
		fmt.Println("[!] Could not detect public IP for SSH restriction. SSH will be open to 0.0.0.0/0.")
	}

	result, err := attacker.DeployEC2(attackerIdentity.GetConfig(), region, operatorIP)
	if err != nil {
		return fmt.Errorf("deploy failed: %v", err)
	}

	fmt.Println()
	if result.IsUpdate {
		fmt.Println("[*] Binary updated.")
	}

	fmt.Println()
	fmt.Println("Connect via SSH:")
	fmt.Printf("    ssh -i %s ec2-user@%s\n", result.KeyFile, result.PublicIP)
	fmt.Println()
	fmt.Println("Connect via SSM:")
	fmt.Printf("    aws ssm start-session --target %s\n", result.InstanceID)
	fmt.Println()
	fmt.Println("Once connected, start a listener:")
	fmt.Printf("    pathrunner attacker listener start --public-ip %s\n", result.PublicIP)
	fmt.Println()

	return nil
}

func (r *REPL) deployEC2Status() error {
	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		// Can still show state from file even without active attacker identity
		state, err := attacker.LoadDeployState()
		if err != nil {
			return fmt.Errorf("failed to load deploy state: %v", err)
		}
		if state.EC2 == nil {
			fmt.Println("No EC2 deployment found.")
			return nil
		}
		// Show saved state without live status check
		r.printEC2State(state.EC2, "unknown (no attacker identity)")
		return nil
	}

	ec2State, instanceStatus, err := attacker.GetEC2Status(attackerIdentity.GetConfig())
	if err != nil {
		return fmt.Errorf("failed to get EC2 status: %v", err)
	}

	if ec2State == nil {
		fmt.Println("No EC2 deployment found.")
		fmt.Println("Use 'attacker infra ec2 create' to deploy pathrunner to an EC2 instance.")
		return nil
	}

	r.printEC2State(ec2State, instanceStatus)
	return nil
}

func (r *REPL) printEC2State(ec2State *attacker.EC2DeployState, status string) {
	fmt.Println("EC2 Deployment:")
	fmt.Println()

	kvPairs := []ui.KV{
		{Key: "Instance", Value: ec2State.InstanceID},
		{Key: "Status", Value: status},
		{Key: "Public IP", Value: ec2State.PublicIP},
		{Key: "Region", Value: ec2State.Region},
		{Key: "Key Pair", Value: ec2State.KeyPairName},
		{Key: "Key File", Value: ec2State.KeyFilePath},
		{Key: "Security Group", Value: ec2State.SecurityGroupID},
	}

	ui.KeyValueTable("", kvPairs)
	fmt.Println()
}

func (r *REPL) deployEC2Destroy() error {
	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required to destroy EC2 resources. Use 'attacker set profile <name>' first")
	}

	if err := attacker.DestroyEC2(attackerIdentity.GetConfig()); err != nil {
		return fmt.Errorf("destroy failed: %v", err)
	}

	fmt.Println("[*] EC2 deployment cleaned up.")
	return nil
}

// --- Bucket subcommands ---

func (r *REPL) cmdDeployBucket(args []string) error {
	if len(args) == 0 {
		// Default action is create
		return r.deployBucketCreate(nil)
	}

	switch args[0] {
	case "create":
		return r.deployBucketCreate(args[1:])
	case "status":
		return r.deployBucketStatus()
	case "destroy":
		return r.deployBucketDestroy(args[1:])
	case "help":
		return r.showDeployBucketHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown deploy bucket action: %s. Use 'attacker infra bucket help'", args[0]))
	}
}

func (r *REPL) deployBucketCreate(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showDeployBucketHelp()
	}

	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required. Use 'attacker set profile <name>' first")
	}

	victimIdentity := r.identityManager.GetCurrent()
	if victimIdentity == nil {
		return fmt.Errorf("victim identity required for cross-account bucket policy. Use 'identity add' first")
	}

	// Get victim account ID from the ARN
	victimAccountID := extractAccountIDFromARN(victimIdentity.CallerARN)
	if victimAccountID == "" {
		return fmt.Errorf("could not determine victim account ID. Run 'whoami' to validate the current identity")
	}

	bucketType := extractFlag(args, "--type")
	if bucketType == "" {
		bucketType = "exfil" // default to exfil since it's more commonly needed
	}
	if bucketType != "code" && bucketType != "exfil" {
		return NewInvalidArgumentsError("--type must be 'code' or 'exfil'")
	}

	region := extractFlag(args, "--region")
	if region == "" {
		region = attackerIdentity.Region
	}

	fmt.Printf("[*] Creating %s bucket in %s...\n", bucketType, region)

	bucketName, err := attacker.DeployBucket(attackerIdentity.GetConfig(), victimAccountID, region, bucketType)
	if err != nil {
		return fmt.Errorf("failed to create bucket: %v", err)
	}

	policyDesc := "Write"
	if bucketType == "code" {
		policyDesc = "Read"
	}
	fmt.Printf("[*] Created bucket: %s\n", bucketName)
	fmt.Printf("[*] %s policy applied for victim account %s\n", policyDesc, victimAccountID)

	return nil
}

func (r *REPL) deployBucketStatus() error {
	buckets, err := attacker.ListDeployedBuckets()
	if err != nil {
		return fmt.Errorf("failed to load bucket state: %v", err)
	}

	if len(buckets) == 0 {
		fmt.Println("No deployed buckets.")
		fmt.Println("Use 'attacker infra bucket create --type <code|exfil>' to create one.")
		return nil
	}

	fmt.Println("Deployed Buckets:")
	fmt.Println()

	rows := make([][]string, 0, len(buckets))
	for _, b := range buckets {
		rows = append(rows, []string{b.Name, b.Type, b.Region})
	}
	ui.Table([]string{"Name", "Type", "Region"}, rows)
	fmt.Println()

	return nil
}

func (r *REPL) deployBucketDestroy(args []string) error {
	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required. Use 'attacker set profile <name>' first")
	}

	bucketName := extractFlag(args, "--name")
	if bucketName != "" {
		// Destroy specific bucket
		fmt.Printf("[*] Destroying bucket %s...\n", bucketName)
		if err := attacker.DestroyBucket(attackerIdentity.GetConfig(), bucketName); err != nil {
			return fmt.Errorf("failed to destroy bucket: %v", err)
		}
		fmt.Println("[*] Bucket destroyed.")
	} else {
		// Destroy all buckets
		buckets, err := attacker.ListDeployedBuckets()
		if err != nil {
			return err
		}
		if len(buckets) == 0 {
			fmt.Println("No deployed buckets to destroy.")
			return nil
		}

		fmt.Printf("[*] Destroying %d bucket(s)...\n", len(buckets))
		if err := attacker.DestroyAllBuckets(attackerIdentity.GetConfig()); err != nil {
			return fmt.Errorf("some buckets failed to destroy: %v", err)
		}
		fmt.Println("[*] All buckets destroyed.")
	}

	return nil
}

// extractAccountIDFromARN extracts the account ID from an AWS ARN.
// ARN format: arn:partition:service:region:account-id:resource
func extractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// --- Global deploy commands ---

func (r *REPL) deployGlobalStatus() error {
	state, err := attacker.LoadDeployState()
	if err != nil {
		return fmt.Errorf("failed to load deploy state: %v", err)
	}

	if !state.HasAnyDeployedResources() {
		fmt.Println("No deployed infrastructure.")
		fmt.Println("Use 'attacker infra ec2 create' to deploy pathrunner to an EC2 instance.")
		return nil
	}

	// EC2 status
	if state.EC2 != nil {
		attackerIdentity := r.identityManager.GetAttackerIdentity()
		if attackerIdentity != nil {
			_, instanceStatus, _ := attacker.GetEC2Status(attackerIdentity.GetConfig())
			r.printEC2State(state.EC2, instanceStatus)
		} else {
			r.printEC2State(state.EC2, "unknown (no attacker identity)")
		}
	}

	// Bucket status
	if len(state.Buckets) > 0 {
		fmt.Println("Buckets:")
		fmt.Println()

		rows := make([][]string, 0, len(state.Buckets))
		for _, b := range state.Buckets {
			rows = append(rows, []string{b.Name, b.Type, b.Region})
		}
		ui.Table([]string{"Name", "Type", "Region"}, rows)
		fmt.Println()
	}

	return nil
}

func (r *REPL) deployGlobalDestroy() error {
	state, err := attacker.LoadDeployState()
	if err != nil {
		return fmt.Errorf("failed to load deploy state: %v", err)
	}

	if !state.HasAnyDeployedResources() {
		fmt.Println("No deployed infrastructure to destroy.")
		return nil
	}

	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required to destroy deployed resources. Use 'attacker set profile <name>' first")
	}

	// Destroy buckets first
	if len(state.Buckets) > 0 {
		fmt.Printf("[*] Destroying %d bucket(s)...\n", len(state.Buckets))
		cfg := attackerIdentity.GetConfig()
		for _, b := range state.Buckets {
			fmt.Printf("[*] Deleting bucket %s...\n", b.Name)
			if err := attacker.DeleteBucket(cfg, b.Name, b.Region); err != nil {
				fmt.Printf("[!] Failed to delete bucket %s: %v\n", b.Name, err)
			}
		}
		state.Buckets = nil
		attacker.SaveDeployState(state)
	}

	// Destroy EC2
	if state.EC2 != nil {
		if err := attacker.DestroyEC2(attackerIdentity.GetConfig()); err != nil {
			return fmt.Errorf("failed to destroy EC2: %v", err)
		}
	}

	fmt.Println("[*] All deployed infrastructure cleaned up.")
	return nil
}

// --- Help text ---

func (r *REPL) showAttackerDeployHelp() error {
	fmt.Println("Attacker Infra Commands:")
	fmt.Println()
	fmt.Println("  attacker infra status                            - Show all deployed infrastructure")
	fmt.Println("  attacker infra destroy                           - Tear down ALL deployed infrastructure")
	fmt.Println()
	fmt.Println("  attacker infra ec2 [create] [--region <region>]  - Deploy pathrunner to EC2")
	fmt.Println("  attacker infra ec2 status                        - Show EC2 instance state")
	fmt.Println("  attacker infra ec2 destroy                       - Tear down EC2 + SG + key pair")
	fmt.Println()
	fmt.Println("  attacker infra bucket [create] [--type code|exfil] - Create an S3 bucket")
	fmt.Println("  attacker infra bucket status                       - Show deployed buckets")
	fmt.Println("  attacker infra bucket destroy [--name <bucket>]    - Destroy bucket(s)")
	fmt.Println()
	fmt.Println("Requires an attacker identity ('attacker set profile <name>').")
	fmt.Println()
	fmt.Println("The EC2 deploy cross-compiles pathrunner for linux/amd64, creates an EC2")
	fmt.Println("instance with SSH + SSM access, and uploads the binary. Re-running 'infra ec2'")
	fmt.Println("when an instance exists updates the binary without recreating infrastructure.")
	return nil
}

func (r *REPL) showDeployEC2Help() error {
	fmt.Println("Deploy EC2 Command:")
	fmt.Println("  attacker infra ec2 [create] [--region <region>]  - Deploy or update pathrunner on EC2")
	fmt.Println("  attacker infra ec2 status                        - Show EC2 instance state")
	fmt.Println("  attacker infra ec2 destroy                       - Tear down EC2 + SG + key pair")
	fmt.Println("  attacker infra ec2 help                          - Show this help message")
	fmt.Println()
	fmt.Println("On first run:")
	fmt.Println("  1. Cross-compiles pathrunner for linux/amd64")
	fmt.Println("  2. Creates EC2 key pair (saved to ~/.pathrunner/keys/)")
	fmt.Println("  3. Creates security group (SSH from your IP, 8443+4444 from 0.0.0.0/0)")
	fmt.Println("  4. Creates IAM instance profile with SSM permissions")
	fmt.Println("  5. Launches t3.micro with Amazon Linux 2023")
	fmt.Println("  6. Uploads binary via SCP")
	fmt.Println()
	fmt.Println("On subsequent runs: re-compiles and uploads the binary only.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  attacker infra ec2")
	fmt.Println("  attacker infra ec2 create --region us-west-2")
	fmt.Println("  attacker infra ec2 status")
	fmt.Println("  attacker infra ec2 destroy")
	return nil
}

func (r *REPL) showDeployBucketHelp() error {
	fmt.Println("Deploy Bucket Command:")
	fmt.Println("  attacker infra bucket [create] [--type code|exfil] [--region <region>]")
	fmt.Println("                                                       - Create an S3 bucket")
	fmt.Println("  attacker infra bucket status                        - Show deployed buckets")
	fmt.Println("  attacker infra bucket destroy [--name <bucket>]     - Destroy specific or all buckets")
	fmt.Println("  attacker infra bucket help                          - Show this help message")
	fmt.Println()
	fmt.Println("Bucket types:")
	fmt.Println("  code   - Code hosting bucket with read-only cross-account policy")
	fmt.Println("  exfil  - Exfiltration bucket with write-only cross-account policy (default)")
	fmt.Println()
	fmt.Println("Requires attacker identity AND a victim identity (for cross-account policy).")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  attacker infra bucket")
	fmt.Println("  attacker infra bucket create --type code --region us-west-2")
	fmt.Println("  attacker infra bucket status")
	fmt.Println("  attacker infra bucket destroy --name pathrunner-exfil-abc123")
	fmt.Println("  attacker infra bucket destroy")
	return nil
}
