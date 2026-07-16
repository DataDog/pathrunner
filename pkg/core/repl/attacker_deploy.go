package repl

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/attacker"
	"github.com/DataDog/pathrunner/pkg/ui"
	"github.com/DataDog/pathrunner/pkg/utils"
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
	case "ecr":
		return r.cmdDeployECR(args[1:])
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
	case "update":
		return r.deployEC2Update()
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

func (r *REPL) deployEC2Update() error {
	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required. Use 'attacker set profile <name>' first")
	}

	result, err := attacker.UpdateEC2(attackerIdentity.GetConfig())
	if err != nil {
		return fmt.Errorf("update failed: %v", err)
	}

	fmt.Println()
	fmt.Println("[*] Binary updated successfully.")
	fmt.Printf("[*] Instance: %s (%s)\n", result.InstanceID, result.PublicIP)
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

	// Collect unique account IDs from all victim identities for the bucket policy
	victimAccountIDs := r.collectVictimAccountIDs()
	if len(victimAccountIDs) == 0 {
		return fmt.Errorf("victim identity required for cross-account bucket policy. Use 'identity add' first")
	}

	if attacker.HasDeployedBuckets() {
		return fmt.Errorf("attacker buckets already deployed. Use 'attacker infra bucket status' to view or 'attacker infra bucket destroy' to recreate")
	}

	region := extractFlag(args, "--region")
	if region == "" {
		region = attackerIdentity.Region
	}

	accountList := strings.Join(victimAccountIDs, ", ")

	fmt.Printf("[*] Creating attacker S3 buckets in %s...\n", region)

	// Create code bucket (read-only for victim — used for hosting payload scripts)
	codeBucket, err := attacker.DeployBucket(attackerIdentity.GetConfig(), victimAccountIDs, region, "code")
	if err != nil {
		return fmt.Errorf("failed to create code bucket: %v", err)
	}
	fmt.Printf("[*] Created code bucket: %s\n", codeBucket)
	fmt.Printf("    Read policy applied for victim account(s): %s\n", accountList)

	// Create exfil bucket (write-only for victim — used for credential exfiltration)
	exfilBucket, err := attacker.DeployBucket(attackerIdentity.GetConfig(), victimAccountIDs, region, "exfil")
	if err != nil {
		return fmt.Errorf("failed to create exfil bucket: %v", err)
	}
	fmt.Printf("[*] Created exfil bucket: %s\n", exfilBucket)
	fmt.Printf("    Write policy applied for victim account(s): %s\n", accountList)

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
		accounts := strings.Join(b.AccountIDs, ", ")
		if accounts == "" {
			accounts = "-"
		}
		rows = append(rows, []string{b.Name, b.Type, b.Region, accounts})
	}
	ui.Table([]string{"Name", "Type", "Region", "Victim Accounts"}, rows)
	fmt.Println()

	return nil
}

func (r *REPL) deployBucketDestroy(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showDeployBucketHelp()
	}

	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required. Use 'attacker set profile <name>' first")
	}

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

	return nil
}

// --- ECR subcommands ---

func (r *REPL) cmdDeployECR(args []string) error {
	if len(args) == 0 {
		return r.deployECRCreate(nil)
	}

	switch args[0] {
	case "create":
		return r.deployECRCreate(args[1:])
	case "status":
		return r.deployECRStatus()
	case "destroy":
		return r.deployECRDestroy(args[1:])
	case "help":
		return r.showDeployECRHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown deploy ecr action: %s. Use 'attacker infra ecr help'", args[0]))
	}
}

func (r *REPL) deployECRCreate(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showDeployECRHelp()
	}

	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required. Use 'attacker set profile <name>' first")
	}

	victimAccountIDs := r.collectVictimAccountIDs()
	if len(victimAccountIDs) == 0 {
		return fmt.Errorf("victim identity required for cross-account ECR pull policy. Use 'identity add' first")
	}

	if attacker.HasDeployedECRRepos() {
		return fmt.Errorf("attacker ECR repos already deployed. Use 'attacker infra ecr status' to view or 'attacker infra ecr destroy' to recreate")
	}

	region := extractFlag(args, "--region")
	if region == "" {
		region = attackerIdentity.Region
	}
	if region == "" {
		region = attackerIdentity.GetConfig().Region
	}
	if region == "" {
		region = "us-east-1"
	}

	accountList := strings.Join(victimAccountIDs, ", ")

	fmt.Printf("[*] Creating attacker ECR repository in %s...\n", region)

	repoName := attacker.DefaultECRRepoName
	repoURI, err := attacker.DeployECR(attackerIdentity.GetConfig(), repoName, victimAccountIDs, region)
	if err != nil {
		return fmt.Errorf("failed to deploy ECR: %v", err)
	}

	fmt.Println()
	fmt.Printf("[*] ECR repository deployed successfully.\n")
	fmt.Printf("    Repository URI: %s\n", repoURI)
	fmt.Printf("    Pull policy applied for victim account(s): %s\n", accountList)
	fmt.Println()
	fmt.Println("Modules that need container images will build and push to this repo automatically.")

	return nil
}

func (r *REPL) deployECRStatus() error {
	repos, err := attacker.ListDeployedECRRepos()
	if err != nil {
		return fmt.Errorf("failed to load ECR state: %v", err)
	}

	if len(repos) == 0 {
		fmt.Println("No deployed ECR repositories.")
		fmt.Println("Use 'attacker infra ecr create' to create one.")
		return nil
	}

	fmt.Println("Deployed ECR Repositories:")
	fmt.Println()

	rows := make([][]string, 0, len(repos))
	for _, repo := range repos {
		accounts := strings.Join(repo.AccountIDs, ", ")
		if accounts == "" {
			accounts = "-"
		}
		rows = append(rows, []string{repo.RepositoryName, repo.Region, repo.RepositoryURI, accounts})
	}
	ui.Table([]string{"Name", "Region", "Repository URI", "Victim Accounts"}, rows)
	fmt.Println()

	return nil
}

func (r *REPL) deployECRDestroy(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showDeployECRHelp()
	}

	attackerIdentity := r.identityManager.GetAttackerIdentity()
	if attackerIdentity == nil {
		return fmt.Errorf("attacker identity required. Use 'attacker set profile <name>' first")
	}

	repos, err := attacker.ListDeployedECRRepos()
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		fmt.Println("No deployed ECR repos to destroy.")
		return nil
	}

	fmt.Printf("[*] Destroying %d ECR repo(s)...\n", len(repos))
	if err := attacker.DestroyAllECRRepos(attackerIdentity.GetConfig()); err != nil {
		return fmt.Errorf("some ECR repos failed to destroy: %v", err)
	}
	fmt.Println("[*] All ECR repos destroyed.")

	return nil
}

// collectVictimAccountIDs returns deduplicated account IDs from all victim
// identities in the identity store. Used to build bucket policies that cover
// every known victim account.
func (r *REPL) collectVictimAccountIDs() []string {
	seen := make(map[string]bool)
	var accountIDs []string
	for _, identity := range r.identityManager.GetIdentities() {
		accountID := utils.ExtractAccountIDFromARN(identity.CallerARN)
		if accountID != "" && !seen[accountID] {
			seen[accountID] = true
			accountIDs = append(accountIDs, accountID)
		}
	}
	return accountIDs
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

	// ECR status
	if len(state.ECRRepos) > 0 {
		fmt.Println("ECR Repositories:")
		fmt.Println()

		rows := make([][]string, 0, len(state.ECRRepos))
		for _, repo := range state.ECRRepos {
			accounts := strings.Join(repo.AccountIDs, ", ")
			if accounts == "" {
				accounts = "-"
			}
			rows = append(rows, []string{repo.RepositoryName, repo.Region, repo.RepositoryURI, accounts})
		}
		ui.Table([]string{"Name", "Region", "Repository URI", "Victim Accounts"}, rows)
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

	// Destroy ECR repos
	if len(state.ECRRepos) > 0 {
		fmt.Printf("[*] Destroying %d ECR repo(s)...\n", len(state.ECRRepos))
		cfg := attackerIdentity.GetConfig()
		for _, r := range state.ECRRepos {
			fmt.Printf("[*] Deleting ECR repo %s...\n", r.RepositoryName)
			if err := attacker.DeleteECRRepository(cfg, r.RepositoryName, r.Region); err != nil {
				fmt.Printf("[!] Failed to delete ECR repo %s: %v\n", r.RepositoryName, err)
			}
		}
		state.ECRRepos = nil
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
	fmt.Println("  attacker infra ec2 update                        - Update binary on existing instance")
	fmt.Println("  attacker infra ec2 status                        - Show EC2 instance state")
	fmt.Println("  attacker infra ec2 destroy                       - Tear down EC2 + SG + key pair")
	fmt.Println()
	fmt.Println("  attacker infra bucket [create] [--region <region>] - Create code + exfil buckets")
	fmt.Println("  attacker infra bucket status                       - Show deployed buckets")
	fmt.Println("  attacker infra bucket destroy                      - Destroy all buckets")
	fmt.Println()
	fmt.Println("  attacker infra ecr [create] [--region <region>]    - Create ECR repo + push container image")
	fmt.Println("  attacker infra ecr status                          - Show deployed ECR repos")
	fmt.Println("  attacker infra ecr destroy                         - Destroy all ECR repos")
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
	fmt.Println("  attacker infra ec2 update                        - Update binary on existing instance")
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
	fmt.Println("  attacker infra bucket [create] [--region <region>]  - Create code + exfil buckets")
	fmt.Println("  attacker infra bucket status                        - Show deployed buckets")
	fmt.Println("  attacker infra bucket destroy                       - Destroy all buckets")
	fmt.Println("  attacker infra bucket help                          - Show this help message")
	fmt.Println()
	fmt.Println("Creates two S3 buckets with cross-account resource policies:")
	fmt.Println("  code   - Read-only policy for victim to pull payload scripts (e.g., Glue jobs)")
	fmt.Println("  exfil  - Write-only policy for victim to push exfiltrated credentials")
	fmt.Println()
	fmt.Println("Requires attacker identity AND a victim identity (for cross-account policy).")
	fmt.Println("Bucket policies are automatically updated when new victim accounts are added.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  attacker infra bucket")
	fmt.Println("  attacker infra bucket create --region us-west-2")
	fmt.Println("  attacker infra bucket status")
	fmt.Println("  attacker infra bucket destroy")
	return nil
}

func (r *REPL) showDeployECRHelp() error {
	fmt.Println("Deploy ECR Command:")
	fmt.Println("  attacker infra ecr [create] [--region <region>]  - Create ECR repo with cross-account pull policy")
	fmt.Println("  attacker infra ecr status                        - Show deployed ECR repos")
	fmt.Println("  attacker infra ecr destroy                       - Destroy all ECR repos")
	fmt.Println("  attacker infra ecr help                          - Show this help message")
	fmt.Println()
	fmt.Println("Creates an ECR repository with a cross-account pull policy so victim accounts")
	fmt.Println("can pull container images from the attacker's ECR repo. Modules that need")
	fmt.Println("container images (e.g. bedrock-003) will automatically build and push their")
	fmt.Println("images to this repo at exploit time.")
	fmt.Println()
	fmt.Println("You can also skip this step entirely — modules auto-create the ECR repo if")
	fmt.Println("one doesn't exist when CONTAINER_URI is not set.")
	fmt.Println()
	fmt.Println("Requires: attacker identity, victim identity (for cross-account policy).")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  attacker infra ecr")
	fmt.Println("  attacker infra ecr create --region us-east-1")
	fmt.Println("  attacker infra ecr status")
	fmt.Println("  attacker infra ecr destroy")
	return nil
}
