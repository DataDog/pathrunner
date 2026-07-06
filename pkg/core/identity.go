package core

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"pathrunner/pkg/discovery"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/ui"
	"pathrunner/pkg/utils"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type IdentityManager struct {
	identities       map[string]*modules.Identity
	current          *modules.Identity
	attackerIdentity *modules.Identity
	getLastResult    func() string
	updateCompletion func()
	autoSwitch       bool // when true, skip interactive prompt and auto-switch
	checkAdmin       bool // when true, skip interactive prompt and auto-check admin
}

func NewIdentityManager(getLastResult func() string, updateCompletion func()) *IdentityManager {
	return &IdentityManager{
		identities:       make(map[string]*modules.Identity),
		getLastResult:    getLastResult,
		updateCompletion: updateCompletion,
	}
}

func (im *IdentityManager) GetCurrent() *modules.Identity {
	return im.current
}

func (im *IdentityManager) GetIdentities() map[string]*modules.Identity {
	return im.identities
}

func (im *IdentityManager) ListIdentities() error {
	if len(im.identities) == 0 {
		fmt.Println("No identities configured.")
		fmt.Println("Use 'identity add' to add credentials.")
		return nil
	}

	rows := make([][]string, 0, len(im.identities))
	for name, identity := range im.identities {
		status := "✓ valid"
		if identity.IsExpired() {
			status = "✗ expired"
		}

		current := ""
		if im.current != nil && im.current.Name == name {
			current = "●"
		}

		source := identity.Profile
		if source == "" {
			switch identity.Type {
			case "env":
				source = "environment"
			case "keys":
				source = "access keys"
			case "assumed_role":
				source = "assumed role"
			default:
				source = identity.Type
			}
		}

		expires := "never"
		if identity.ExpiresAt != nil {
			expires = identity.ExpiresAt.Format("15:04:05")
		} else if identity.Type == "profile" {
			expires = "auto-refresh"
		}

		admin := "-"
		if identity.IsAdmin != nil {
			if *identity.IsAdmin {
				admin = "Yes"
			} else {
				admin = "No"
			}
		}

		rows = append(rows, []string{name, identity.CallerARN, identity.Type, source, expires, admin, status, current})
	}

	fmt.Println("Configured identities:")
	fmt.Println()
	ui.Table([]string{"Name", "ARN", "Type", "Profile/Source", "Expires", "Admin", "Status", "Current"}, rows)
	fmt.Println()

	if im.current != nil {
		fmt.Printf("Current identity: %s\n", im.current.Name)
	} else {
		fmt.Println("No current identity selected.")
	}

	return nil
}

func (im *IdentityManager) ShowCurrent() error {
	if im.current == nil {
		fmt.Println("No current identity selected.")
		return nil
	}

	// Use cached CallerARN if available, otherwise call STS
	callerARN := im.current.CallerARN
	account := ""
	if callerARN == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		stsClient := sts.NewFromConfig(im.current.GetConfig())
		result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			fmt.Printf("Error getting caller identity: %v\n", err)
			return nil
		}
		callerARN = aws.ToString(result.Arn)
		account = aws.ToString(result.Account)
		im.current.CallerARN = callerARN
	} else {
		// Extract account from ARN (arn:aws:iam::123456789012:...)
		parts := strings.Split(callerARN, ":")
		if len(parts) >= 5 {
			account = parts[4]
		}
	}

	kvPairs := []ui.KV{
		{Key: "Name", Value: im.current.Name},
		{Key: "Type", Value: im.current.Type},
		{Key: "Region", Value: im.current.Region},
	}

	if im.current.Profile != "" {
		kvPairs = append(kvPairs, ui.KV{Key: "Profile", Value: im.current.Profile})
	}

	kvPairs = append(kvPairs, ui.KV{Key: "Account", Value: account})
	kvPairs = append(kvPairs, ui.KV{Key: "User/Role ARN", Value: callerARN})

	if im.current.IsAdmin != nil {
		if *im.current.IsAdmin {
			kvPairs = append(kvPairs, ui.KV{Key: "Admin", Value: "Yes"})
		} else {
			kvPairs = append(kvPairs, ui.KV{Key: "Admin", Value: "No"})
		}
	} else {
		kvPairs = append(kvPairs, ui.KV{Key: "Admin", Value: "- (not checked)"})
	}

	if im.current.ExpiresAt != nil {
		kvPairs = append(kvPairs, ui.KV{Key: "Expires", Value: im.current.ExpiresAt.Format("2006-01-02 15:04:05 MST")})
		if im.current.IsExpired() {
			kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: "EXPIRED"})
		} else {
			kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: "Valid"})
		}
	} else {
		kvPairs = append(kvPairs, ui.KV{Key: "Status", Value: "Valid (no expiration)"})
	}

	fmt.Printf("Current Identity: %s\n", im.current.Name)
	fmt.Println()
	ui.KeyValueTable("", kvPairs)
	fmt.Println()

	return nil
}

// hasFlag checks if a boolean flag is present in the args
func (im *IdentityManager) hasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}

// removeFlag removes a boolean flag from args
func (im *IdentityManager) removeFlag(args []string, flag string) []string {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != flag {
			result = append(result, arg)
		}
	}
	return result
}

// AddIdentityFromCredentials adds an identity directly from pre-validated credential
// fields, bypassing the arg-parsing layer. Used by the listener's /collect endpoint
// where inputs come from the internet and must not pass through flag extraction.
func (im *IdentityManager) AddIdentityFromCredentials(accessKey, secret, token, region, name string) error {
	return im.addFromKeys(accessKey, secret, token, name, region)
}

func (im *IdentityManager) AddIdentity(args []string) error {
	if len(args) == 0 {
		return im.addFromEnvironment()
	}

	// Check for --switch flag (auto-switch without prompting)
	im.autoSwitch = im.hasFlag(args, "--switch")
	args = im.removeFlag(args, "--switch")
	defer func() { im.autoSwitch = false }()

	// Check for --check-admin flag (auto-check admin without prompting)
	im.checkAdmin = im.hasFlag(args, "--check-admin")
	args = im.removeFlag(args, "--check-admin")
	defer func() { im.checkAdmin = false }()

	if len(args) == 0 {
		return im.addFromEnvironment()
	}

	switch args[0] {
	case "--from-output":
		customName := im.extractNameFlag(args[1:])
		return im.addFromLastOutput(customName)
	case "--from-file":
		if len(args) < 2 {
			return fmt.Errorf("--from-file requires file path")
		}
		filePath := args[1]
		customName := im.extractNameFlag(args[2:])
		return im.addFromFile(filePath, customName)
	case "--from-clipboard":
		customName := im.extractNameFlag(args[1:])
		return im.addFromClipboard(customName)
	case "--profile":
		if len(args) < 2 {
			return fmt.Errorf("--profile requires profile name")
		}
		return im.addFromProfile(args[1])
	case "--access":
		secretKey := im.extractFlag(args[1:], "--secret")
		if secretKey == "" {
			return fmt.Errorf("--secret is required when using --access")
		}
		sessionToken := im.extractFlag(args[1:], "--token")
		customName := im.extractFlag(args[1:], "--name")
		region := im.extractFlag(args[1:], "--region")
		return im.addFromKeys(args[1], secretKey, sessionToken, customName, region)
	default:
		return fmt.Errorf("unknown add option: %s", args[0])
	}
}

// extractFlag extracts the value for a given --flag from args
func (im *IdentityManager) extractFlag(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// extractNameFlag extracts the --name flag value from args
func (im *IdentityManager) extractNameFlag(args []string) string {
	return im.extractFlag(args, "--name")
}

// promptForIdentityName prompts the user to provide a custom name for the identity
// Returns the custom name if provided, or empty string if user declines
func (im *IdentityManager) promptForIdentityName(suggestedName string) string {
	fmt.Printf("\nSuggested identity name: %s\n", suggestedName)
	fmt.Print("Enter a custom name (or press Enter to use suggested name): ")

	// Use bufio.Reader to properly handle input without leaving buffer residue
	reader := bufio.NewReader(os.Stdin)
	customName, err := reader.ReadString('\n')
	if err != nil {
		// If there's an error reading, just use the suggested name
		return suggestedName
	}

	customName = strings.TrimSpace(customName)
	if customName == "" {
		return suggestedName
	}

	return customName
}

func (im *IdentityManager) addFromEnvironment() error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to load AWS config from environment: %v", err)
	}

	identity := &modules.Identity{
		Name:   "default",
		Type:   "env",
		Region: cfg.Region,
	}
	identity.SetConfig(cfg)

	if err := identity.Validate(); err != nil {
		return fmt.Errorf("environment credentials validation failed: %v", err)
	}

	im.identities[identity.Name] = identity
	if im.current == nil {
		im.current = identity
	}

	// Update completion with new identity
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	fmt.Printf("Added identity '%s' from environment variables\n", identity.Name)

	// Prompt for admin check, then to switch
	im.promptForAdminCheck(identity.Name)
	im.promptToSwitch(identity.Name)
	return nil
}

func (im *IdentityManager) addFromProfile(profileName string) error {
	// Test that profile exists by trying to load it once
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(profileName))
	if err != nil {
		return fmt.Errorf("failed to load AWS profile '%s': %v", profileName, err)
	}

	// If profile doesn't specify a region, use a default
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
		fmt.Println("Profile does not specify a region, using default: us-east-1")
	}

	identity := &modules.Identity{
		Name:    profileName,
		Type:    "profile",
		Profile: profileName,
		Region:  region,
	}
	// Store minimal config for fallback, but GetConfig() will create fresh ones
	identity.SetConfig(cfg)

	// Validate that the profile works - this will use GetConfig() which creates fresh config
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("profile credentials validation failed: %v", err)
	}

	im.identities[identity.Name] = identity
	if im.current == nil {
		im.current = identity
	}

	// Update completion with new identity
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	fmt.Printf("Added identity '%s' from AWS profile\n", identity.Name)
	fmt.Printf("Profile credentials will be refreshed automatically on each use\n")

	// Prompt for admin check, then to switch
	im.promptForAdminCheck(identity.Name)
	im.promptToSwitch(identity.Name)
	return nil
}

func (im *IdentityManager) addFromKeys(accessKeyID, secretKey, sessionToken, customName, region string) error {
	creds := credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, sessionToken)

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(creds))
	if err != nil {
		return fmt.Errorf("failed to create config from keys: %v", err)
	}

	// Resolve region: explicit flag > config default > us-east-1
	resolvedRegion := region
	if resolvedRegion == "" {
		resolvedRegion = cfg.Region
	}
	if resolvedRegion == "" {
		resolvedRegion = "us-east-1"
	}
	cfg.Region = resolvedRegion

	name := customName
	if name == "" {
		name = fmt.Sprintf("keys_%s", accessKeyID[len(accessKeyID)-4:])
	}

	identity := &modules.Identity{
		Name:         name,
		Type:         "keys",
		AccessKeyID:  accessKeyID,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Region:       resolvedRegion,
	}
	identity.SetConfig(cfg)

	if sessionToken != "" {
		expiresAt := time.Now().Add(1 * time.Hour)
		identity.ExpiresAt = &expiresAt
	}

	if err := identity.Validate(); err != nil {
		return fmt.Errorf("access key credentials validation failed: %v", err)
	}

	im.identities[identity.Name] = identity
	if im.current == nil {
		im.current = identity
	}

	// Update completion with new identity
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	fmt.Printf("Added identity '%s' from access keys\n", identity.Name)

	// Prompt for admin check, then to switch
	im.promptForAdminCheck(identity.Name)
	im.promptToSwitch(identity.Name)
	return nil
}

func (im *IdentityManager) addFromLastOutput(customName string) error {
	fmt.Println("Parsing credentials from last command output...")

	if im.getLastResult == nil {
		return fmt.Errorf("no result retrieval function available")
	}

	lastResult := im.getLastResult()
	if lastResult == "" {
		return fmt.Errorf("no previous exploit output available")
	}

	extractedCreds, err := utils.ExtractCredentialsFromText(lastResult)
	if err != nil {
		return fmt.Errorf("failed to extract credentials: %v", err)
	}

	// Create AWS credentials provider
	creds := credentials.NewStaticCredentialsProvider(
		extractedCreds.AccessKeyID,
		extractedCreds.SecretAccessKey,
		extractedCreds.SessionToken,
	)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(creds),
		config.WithRegion(extractedCreds.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to create config from extracted credentials: %v", err)
	}

	// Determine identity name
	var identityName string
	if customName != "" {
		// Use the --name flag value
		identityName = customName
	} else {
		// Prompt user for a custom name
		suggestedName := extractedCreds.GenerateIdentityName()
		identityName = im.promptForIdentityName(suggestedName)
	}

	identity := &modules.Identity{
		Name:         identityName,
		Type:         "keys",
		AccessKeyID:  extractedCreds.AccessKeyID,
		SecretKey:    extractedCreds.SecretAccessKey,
		SessionToken: extractedCreds.SessionToken,
		Region:       extractedCreds.Region,
	}
	identity.SetConfig(cfg)

	// Set expiration for session tokens (typically 1 hour for Lambda roles)
	if extractedCreds.SessionToken != "" {
		expiresAt := time.Now().Add(1 * time.Hour)
		identity.ExpiresAt = &expiresAt
	}

	// Validate the credentials
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("extracted credentials validation failed: %v", err)
	}

	// Add to identity manager
	im.identities[identity.Name] = identity

	// Switch to the new identity if no current identity
	if im.current == nil {
		im.current = identity
	}

	// Update completion with new identity
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	fmt.Printf("Successfully added identity '%s' from exploit output\n", identity.Name)
	fmt.Printf("Source: %s\n", extractedCreds.Source)
	fmt.Printf("Access Key: %s\n", extractedCreds.AccessKeyID)
	fmt.Printf("Region: %s\n", extractedCreds.Region)
	if extractedCreds.SessionToken != "" {
		fmt.Printf("Session Token: Present (expires in ~1 hour)\n")
	}

	// Prompt for admin check, then to switch
	im.promptForAdminCheck(identity.Name)
	im.promptToSwitch(identity.Name)

	return nil
}

func (im *IdentityManager) addFromFile(filePath string, customName string) error {
	fmt.Printf("Reading credentials from file: %s\n", filePath)

	// Read file contents
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	fileContent := string(fileData)
	if fileContent == "" {
		return fmt.Errorf("file is empty")
	}

	// Extract credentials using the same logic as --from-output
	extractedCreds, err := utils.ExtractCredentialsFromText(fileContent)
	if err != nil {
		return fmt.Errorf("failed to extract credentials: %v", err)
	}

	// Create AWS credentials provider
	creds := credentials.NewStaticCredentialsProvider(
		extractedCreds.AccessKeyID,
		extractedCreds.SecretAccessKey,
		extractedCreds.SessionToken,
	)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(creds),
		config.WithRegion(extractedCreds.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to create config from extracted credentials: %v", err)
	}

	// Determine identity name
	var identityName string
	if customName != "" {
		// Use the --name flag value
		identityName = customName
	} else {
		// Prompt user for a custom name
		suggestedName := extractedCreds.GenerateIdentityName()
		identityName = im.promptForIdentityName(suggestedName)
	}

	identity := &modules.Identity{
		Name:         identityName,
		Type:         "keys",
		AccessKeyID:  extractedCreds.AccessKeyID,
		SecretKey:    extractedCreds.SecretAccessKey,
		SessionToken: extractedCreds.SessionToken,
		Region:       extractedCreds.Region,
	}
	identity.SetConfig(cfg)

	// Set expiration for session tokens
	if extractedCreds.SessionToken != "" {
		expiresAt := time.Now().Add(1 * time.Hour)
		identity.ExpiresAt = &expiresAt
	}

	// Validate the credentials
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("extracted credentials validation failed: %v", err)
	}

	// Add to identity manager
	im.identities[identity.Name] = identity

	// Switch to the new identity if no current identity
	if im.current == nil {
		im.current = identity
	}

	// Update completion with new identity
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	fmt.Printf("Successfully added identity '%s' from file\n", identity.Name)
	fmt.Printf("Source: %s\n", extractedCreds.Source)
	fmt.Printf("Access Key: %s\n", extractedCreds.AccessKeyID)
	fmt.Printf("Region: %s\n", extractedCreds.Region)
	if extractedCreds.SessionToken != "" {
		fmt.Printf("Session Token: Present (expires in ~1 hour)\n")
	}

	// Prompt for admin check, then to switch
	im.promptForAdminCheck(identity.Name)
	im.promptToSwitch(identity.Name)

	return nil
}

func (im *IdentityManager) addFromClipboard(customName string) error {
	fmt.Println("Attempting to read from clipboard...")

	// Try to read from OS clipboard first
	clipboardText, err := readOSClipboard()

	if err != nil || clipboardText == "" {
		// Clipboard failed or empty, prompt user to paste
		fmt.Println("Unable to read from system clipboard.")
		fmt.Println("Please paste your credentials below, then press Ctrl+D (or Cmd+D on Mac):")
		fmt.Println("Note: In REPL mode, use 'identity add --from-file <path>' for multi-line credentials.")
		fmt.Println()

		// Read from stdin until EOF
		var input strings.Builder
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			input.WriteString(scanner.Text())
			input.WriteString("\n")
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read input: %v", err)
		}

		clipboardText = input.String()
	} else {
		fmt.Println("Successfully read from system clipboard")
		fmt.Println("Note: Do not paste anything - credentials already captured from clipboard")
	}

	if strings.TrimSpace(clipboardText) == "" {
		return fmt.Errorf("no input provided")
	}

	// Extract credentials using the same logic as --from-output
	extractedCreds, err := utils.ExtractCredentialsFromText(clipboardText)
	if err != nil {
		return fmt.Errorf("failed to extract credentials: %v", err)
	}

	// Create AWS credentials provider
	creds := credentials.NewStaticCredentialsProvider(
		extractedCreds.AccessKeyID,
		extractedCreds.SecretAccessKey,
		extractedCreds.SessionToken,
	)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(creds),
		config.WithRegion(extractedCreds.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to create config from extracted credentials: %v", err)
	}

	// Determine identity name
	var identityName string
	if customName != "" {
		// Use the --name flag value
		identityName = customName
	} else {
		// Prompt user for a custom name
		suggestedName := extractedCreds.GenerateIdentityName()
		identityName = im.promptForIdentityName(suggestedName)
	}

	identity := &modules.Identity{
		Name:         identityName,
		Type:         "keys",
		AccessKeyID:  extractedCreds.AccessKeyID,
		SecretKey:    extractedCreds.SecretAccessKey,
		SessionToken: extractedCreds.SessionToken,
		Region:       extractedCreds.Region,
	}
	identity.SetConfig(cfg)

	// Set expiration for session tokens
	if extractedCreds.SessionToken != "" {
		expiresAt := time.Now().Add(1 * time.Hour)
		identity.ExpiresAt = &expiresAt
	}

	// Validate the credentials
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("extracted credentials validation failed: %v", err)
	}

	// Add to identity manager
	im.identities[identity.Name] = identity

	// Switch to the new identity if no current identity
	if im.current == nil {
		im.current = identity
	}

	// Update completion with new identity
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	fmt.Printf("Successfully added identity '%s' from clipboard\n", identity.Name)
	fmt.Printf("Source: %s\n", extractedCreds.Source)
	fmt.Printf("Access Key: %s\n", extractedCreds.AccessKeyID)
	fmt.Printf("Region: %s\n", extractedCreds.Region)
	if extractedCreds.SessionToken != "" {
		fmt.Printf("Session Token: Present (expires in ~1 hour)\n")
	}

	// Prompt for admin check, then to switch
	im.promptForAdminCheck(identity.Name)
	im.promptToSwitch(identity.Name)

	return nil
}

func (im *IdentityManager) SwitchIdentity(name string) error {
	identity, exists := im.identities[name]
	if !exists {
		return fmt.Errorf("identity '%s' not found", name)
	}

	if identity.IsExpired() {
		return fmt.Errorf("identity '%s' has expired", name)
	}

	im.current = identity
	fmt.Printf("Switched to identity: %s\n", name)

	return nil
}

func (im *IdentityManager) RemoveIdentity(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("identity clear requires identity name or --expired flag")
	}

	// Check if --expired flag is provided
	if args[0] == "--expired" {
		return im.removeExpiredIdentities()
	}

	// Remove specific identity by name
	identityName := args[0]

	if _, exists := im.identities[identityName]; !exists {
		return fmt.Errorf("identity '%s' not found", identityName)
	}

	// Don't allow removing current identity
	if im.current != nil && im.current.Name == identityName {
		return fmt.Errorf("cannot remove current identity '%s'. Switch to another identity first", identityName)
	}

	delete(im.identities, identityName)
	fmt.Printf("Removed identity: %s\n", identityName)

	// Update completion with removed identity
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	return nil
}

func (im *IdentityManager) removeExpiredIdentities() error {
	var removed []string

	for name, identity := range im.identities {
		if identity.IsExpired() {
			// Don't remove current identity even if expired
			if im.current != nil && im.current.Name == name {
				fmt.Printf("Skipping current identity '%s' (switch to another identity first)\n", name)
				continue
			}
			delete(im.identities, name)
			removed = append(removed, name)
		}
	}

	if len(removed) == 0 {
		fmt.Println("No expired identities to remove.")
		return nil
	}

	fmt.Printf("Removed %d expired identities:\n", len(removed))
	for _, name := range removed {
		fmt.Printf("  - %s\n", name)
	}

	// Update completion with removed identities
	if im.updateCompletion != nil {
		im.updateCompletion()
	}

	return nil
}

func (im *IdentityManager) RefreshCurrentIdentity() error {
	if im.current == nil {
		return fmt.Errorf("no current identity to refresh")
	}

	if im.current.Type == "profile" {
		fmt.Printf("Profile identities are automatically refreshed on each use.\n")
		fmt.Printf("No manual refresh needed for profile '%s'.\n", im.current.Profile)
		return nil
	}

	return im.current.RefreshConfig()
}

// SetIdentities sets all identities at once (used when loading from session)
func (im *IdentityManager) SetIdentities(identities map[string]*modules.Identity) {
	im.identities = identities
}

// SetCurrent sets the current identity (used when loading from session)
func (im *IdentityManager) SetCurrent(identity *modules.Identity) {
	im.current = identity
}

// GetAttackerIdentity returns the configured attacker account identity, or nil.
func (im *IdentityManager) GetAttackerIdentity() *modules.Identity {
	return im.attackerIdentity
}

// SetAttackerIdentity sets the attacker account identity.
func (im *IdentityManager) SetAttackerIdentity(identity *modules.Identity) {
	im.attackerIdentity = identity
}

// ClearAttackerIdentity removes the attacker account identity.
func (im *IdentityManager) ClearAttackerIdentity() {
	im.attackerIdentity = nil
}

// CheckAdmin checks whether the named identity (or current if empty) has admin privileges.
func (im *IdentityManager) CheckAdmin(identityName string) error {
	var identity *modules.Identity
	if identityName == "" {
		identity = im.current
		if identity == nil {
			return fmt.Errorf("no current identity selected")
		}
		identityName = identity.Name
	} else {
		var exists bool
		identity, exists = im.identities[identityName]
		if !exists {
			return fmt.Errorf("identity '%s' not found", identityName)
		}
	}

	// Get the caller ARN — use cached value or call STS
	principalARN := identity.CallerARN
	if principalARN == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		stsClient := sts.NewFromConfig(identity.GetConfig())
		result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return fmt.Errorf("failed to get caller identity: %v", err)
		}
		principalARN = aws.ToString(result.Arn)
		identity.CallerARN = principalARN
	}

	fmt.Printf("Checking admin privileges for '%s' (%s)...\n", identityName, principalARN)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	adminResult, err := discovery.CheckAdminPrivileges(ctx, identity.GetConfig(), principalARN)
	if err != nil {
		fmt.Printf("Admin check failed: %v\n", err)
		fmt.Println("The identity may lack iam:SimulatePrincipalPolicy permission.")
		return nil
	}

	isAdmin := adminResult.IsAdmin
	identity.IsAdmin = &isAdmin

	if adminResult.IsAdmin {
		fmt.Printf("Result: %s is an ADMIN (%d/%d actions allowed)\n",
			identityName, adminResult.AllowedCount, adminResult.AllowedCount+adminResult.DeniedCount)
	} else {
		fmt.Printf("Result: %s is NOT an admin (%d/%d actions allowed)\n",
			identityName, adminResult.AllowedCount, adminResult.AllowedCount+adminResult.DeniedCount)
		if len(adminResult.DeniedActions) > 0 {
			fmt.Printf("Denied: %s\n", strings.Join(adminResult.DeniedActions, ", "))
		}
	}

	return nil
}

// promptForAdminCheck checks admin privileges only when --check-admin flag is set.
func (im *IdentityManager) promptForAdminCheck(identityName string) {
	if im.checkAdmin {
		im.CheckAdmin(identityName)
	}
}

// promptToSwitch asks the user if they want to switch to the new identity
func (im *IdentityManager) promptToSwitch(identityName string) {
	// Only prompt if there's already a current identity (not auto-switching)
	if im.current == nil || im.current.Name == identityName {
		return
	}

	if im.autoSwitch {
		im.current = im.identities[identityName]
		fmt.Printf("Switched to identity: %s\n", identityName)
		return
	}

	fmt.Printf("Switch to identity '%s'? [y/N]: ", identityName)
	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		im.current = im.identities[identityName]
		fmt.Printf("Switched to identity: %s\n", identityName)
	}
}

// readOSClipboard attempts to read from the system clipboard
// Returns the clipboard contents or an error if unable to read
func readOSClipboard() (string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin": // macOS
		cmd = exec.Command("pbpaste")
	case "linux":
		// Try xclip first, then xsel, then wl-paste (Wayland)
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard", "-o")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--output")
		} else if _, err := exec.LookPath("wl-paste"); err == nil {
			cmd = exec.Command("wl-paste")
		} else {
			return "", fmt.Errorf("no clipboard utility found (install xclip, xsel, or wl-clipboard)")
		}
	case "windows":
		cmd = exec.Command("powershell.exe", "-command", "Get-Clipboard")
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to read clipboard: %v", err)
	}

	return string(output), nil
}
