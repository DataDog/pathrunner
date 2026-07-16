package resources

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var accountIDPattern = regexp.MustCompile(`(\d{12})$`)

// DefaultCloudfoxDir returns the default cloudfox output directory.
func DefaultCloudfoxDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".cloudfox", "cloudfox-output", "aws")
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir
	}
	return ""
}

// FindProfileDirs discovers cloudfox profile directories under basePath.
// Returns a map of accountID -> directory path.
// If accountIDs filter is provided, only returns matching accounts.
func FindProfileDirs(basePath string, accountIDs []string) (map[string]ProfileDir, error) {
	if basePath == "" {
		basePath = DefaultCloudfoxDir()
	}
	if basePath == "" {
		return nil, fmt.Errorf("could not find cloudfox output directory")
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cloudfox directory %s: %w", basePath, err)
	}

	wantAll := len(accountIDs) == 0
	wantSet := make(map[string]bool, len(accountIDs))
	for _, id := range accountIDs {
		wantSet[id] = true
	}

	result := make(map[string]ProfileDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		profile, accountID := extractProfileAndAccountID(name)
		if accountID == "" {
			continue
		}
		if wantAll || wantSet[accountID] {
			result[accountID] = ProfileDir{
				Path:      filepath.Join(basePath, name),
				Profile:   profile,
				AccountID: accountID,
			}
		}
	}

	return result, nil
}

// ProfileDir holds a discovered cloudfox profile directory.
type ProfileDir struct {
	Path      string
	Profile   string
	AccountID string
}

// extractProfileAndAccountID parses a cloudfox directory name like "ddplp-697683661464".
// The account ID is always the trailing 12-digit number.
func extractProfileAndAccountID(dirName string) (profile string, accountID string) {
	match := accountIDPattern.FindStringSubmatch(dirName)
	if len(match) < 2 {
		return "", ""
	}
	accountID = match[1]
	// Profile is everything before the trailing "-{accountID}"
	prefix := strings.TrimSuffix(dirName, accountID)
	profile = strings.TrimSuffix(prefix, "-")
	return profile, accountID
}

// hasCloudfoxData checks if a directory contains cloudfox output (json/ or loot/ subdirectory).
func hasCloudfoxData(dirPath string) bool {
	jsonDir := filepath.Join(dirPath, "json")
	if fi, err := os.Stat(jsonDir); err == nil && fi.IsDir() {
		return true
	}
	lootDir := filepath.Join(dirPath, "loot")
	if fi, err := os.Stat(lootDir); err == nil && fi.IsDir() {
		return true
	}
	return false
}

// ImportFromDir imports all available cloudfox data from a profile directory.
// It opportunistically reads whatever files are present and returns the merged resources.
func ImportFromDir(dirPath string) (*AccountResources, []string, error) {
	jsonDir := filepath.Join(dirPath, "json")
	lootDir := filepath.Join(dirPath, "loot")

	// Determine account ID from directory name
	profile, accountID := extractProfileAndAccountID(filepath.Base(dirPath))
	if accountID == "" {
		// Try to extract from the first JSON file we can parse
		accountID, profile = probeAccountID(jsonDir)
		if accountID == "" {
			return nil, nil, fmt.Errorf("could not determine account ID from directory %s", dirPath)
		}
	}

	var allResources []Resource
	var filesParsed []string
	var accessKeyIDs []string

	// Parse JSON files in priority order, each one opportunistically
	type jsonParser struct {
		filename string
		parse    func(path string, accountID string) []Resource
	}

	parsers := []jsonParser{
		{"workloads.json", parseWorkloads},
		{"principals.json", parsePrincipals},
		{"buckets.json", parseBuckets},
		{"databases.json", parseDatabases},
		{"secrets.json", parseSecrets},
		{"endpoints.json", parseEndpoints},
		{"role-trusts-principals.json", parseRoleTrusts},
		{"access-keys.json", parseAccessKeys},
		{"instances.json", parseInstances},
	}

	for _, p := range parsers {
		path := filepath.Join(jsonDir, p.filename)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		resources := p.parse(path, accountID)
		if len(resources) > 0 {
			allResources = append(allResources, resources...)
			filesParsed = append(filesParsed, "json/"+p.filename)
		}
	}

	// Parse loot files
	accessKeysLootPath := filepath.Join(lootDir, "access-keys.txt")
	if _, err := os.Stat(accessKeysLootPath); err == nil {
		accessKeyIDs = parseAccessKeyIDsFromLoot(accessKeysLootPath)
		if len(accessKeyIDs) > 0 {
			filesParsed = append(filesParsed, "loot/access-keys.txt")
		}
	}

	inventoryLootPath := filepath.Join(lootDir, "inventory.txt")
	if _, err := os.Stat(inventoryLootPath); err == nil {
		arnResources := parseInventoryARNs(inventoryLootPath, accountID)
		if len(arnResources) > 0 {
			allResources = append(allResources, arnResources...)
			filesParsed = append(filesParsed, "loot/inventory.txt")
		}
	}

	// Deduplicate by ARN, merging properties
	deduped := deduplicateResources(allResources)

	ar := &AccountResources{
		AccountID: accountID,
		Imports: []ImportRecord{
			{
				SourceDir:   dirPath,
				Profile:     profile,
				ImportedAt:  time.Now(),
				FilesParsed: filesParsed,
			},
		},
		Resources: deduped,
	}

	return ar, accessKeyIDs, nil
}

// probeAccountID tries to extract the account ID from the first parseable JSON file.
func probeAccountID(jsonDir string) (accountID string, profile string) {
	// Try workloads.json first since it's the primary source
	for _, filename := range []string{"workloads.json", "principals.json", "instances.json", "lambda.json"} {
		path := filepath.Join(jsonDir, filename)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var records []map[string]string
		if err := json.Unmarshal(data, &records); err != nil || len(records) == 0 {
			continue
		}
		if acct, ok := records[0]["Account"]; ok && len(acct) == 12 {
			return acct, ""
		}
	}
	return "", ""
}

// deduplicateResources merges resources by ARN. For resources without ARNs,
// they are deduplicated by service+name. Later entries supplement existing records.
func deduplicateResources(resources []Resource) []Resource {
	seen := make(map[string]int) // key -> index in result
	var result []Resource

	for _, r := range resources {
		key := r.ARN
		if key == "" {
			key = r.Service + ":" + r.Name
		}

		if idx, exists := seen[key]; exists {
			// Supplement existing record with new properties
			existing := &result[idx]
			if existing.Role == "" && r.Role != "" {
				existing.Role = r.Role
			}
			if existing.Region == "" && r.Region != "" {
				existing.Region = r.Region
			}
			if existing.IsAdmin == "" && r.IsAdmin != "" {
				existing.IsAdmin = r.IsAdmin
			}
			if existing.CanPrivEsc == "" && r.CanPrivEsc != "" {
				existing.CanPrivEsc = r.CanPrivEsc
			}
			if existing.Public == "" && r.Public != "" {
				existing.Public = r.Public
			}
			if r.Properties != nil {
				if existing.Properties == nil {
					existing.Properties = make(map[string]string)
				}
				for k, v := range r.Properties {
					if _, has := existing.Properties[k]; !has {
						existing.Properties[k] = v
					}
				}
			}
		} else {
			seen[key] = len(result)
			result = append(result, r)
		}
	}

	return result
}

// readJSONArray reads a cloudfox JSON file (always a top-level array of flat objects).
func readJSONArray(path string) ([]map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []map[string]string
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func parseWorkloads(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		resourceType := strings.ToLower(r["Service"])
		if resourceType == "ec2" {
			resourceType = "instance"
		} else if resourceType == "lambda" {
			resourceType = "function"
		}
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Name"],
			ARN:          r["Arn"],
			Service:      r["Service"],
			ResourceType: resourceType,
			Region:       r["Region"],
			Role:         r["Role"],
			IsAdmin:      normalizeFlag(r["IsAdminRole?"]),
			CanPrivEsc:   normalizeFlag(r["CanPrivEscToAdmin?"]),
		})
	}
	return resources
}

func parsePrincipals(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		principalType := strings.ToLower(r["Type"])
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Name"],
			ARN:          r["Arn"],
			Service:      "IAM",
			ResourceType: principalType,
			IsAdmin:      normalizeFlag(r["IsAdminRole?"]),
			CanPrivEsc:   normalizeFlag(r["CanPrivEscToAdmin?"]),
			Properties: buildProperties(map[string]string{
				"AttachedPolicies": r["AttachedPolicies"],
				"InlinePolicies":   r["InlinePolicies"],
			}),
		})
	}
	return resources
}

func parseBuckets(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		// Construct ARN since cloudfox buckets don't include one
		arn := "arn:aws:s3:::" + r["Name"]
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Name"],
			ARN:          arn,
			Service:      "S3",
			ResourceType: "bucket",
			Region:       r["Region"],
			Public:       normalizeFlag(r["Public?"]),
			Properties: buildProperties(map[string]string{
				"ResourcePolicySummary": r["Resource Policy Summary"],
			}),
		})
	}
	return resources
}

func parseDatabases(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Name"],
			Service:      r["Service"],
			ResourceType: "database",
			Region:       r["Region"],
			Properties: buildProperties(map[string]string{
				"Engine":   r["Engine"],
				"Size":     r["Size"],
				"Endpoint": r["Endpoint"],
				"Port":     r["Port"],
				"UserName": r["UserName"],
				"Roles":    r["Roles"],
			}),
		})
	}
	return resources
}

func parseSecrets(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Name"],
			Service:      r["Service"],
			ResourceType: "secret",
			Region:       r["Region"],
			Properties: buildProperties(map[string]string{
				"Description": r["Description"],
			}),
		})
	}
	return resources
}

func parseEndpoints(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Name"],
			Service:      r["Service"],
			ResourceType: "endpoint",
			Region:       r["Region"],
			Public:       normalizeFlag(r["Public"]),
			Properties: buildProperties(map[string]string{
				"Endpoint": r["Endpoint"],
				"Port":     r["Port"],
				"Protocol": r["Protocol"],
			}),
		})
	}
	return resources
}

func parseRoleTrusts(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Role Name"],
			ARN:          r["Role Arn"],
			Service:      "IAM",
			ResourceType: "role-trust",
			IsAdmin:      normalizeFlag(r["IsAdmin?"]),
			CanPrivEsc:   normalizeFlag(r["CanPrivEscToAdmin?"]),
			Properties: buildProperties(map[string]string{
				"TrustedPrincipal": r["Trusted Principal"],
				"ExternalID":      r["ExternalID"],
			}),
		})
	}
	return resources
}

func parseAccessKeys(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["User Name"],
			Service:      "IAM",
			ResourceType: "access-key",
			Properties: buildProperties(map[string]string{
				"AccessKeyID": r["Access Key ID"],
			}),
		})
	}
	return resources
}

func parseInstances(path string, accountID string) []Resource {
	records, err := readJSONArray(path)
	if err != nil {
		return nil
	}
	var resources []Resource
	for _, r := range records {
		// Construct ARN from instance ID and zone
		region := ""
		zone := r["Zone"]
		if zone != "" {
			// Zone is like "us-east-1a", region is "us-east-1"
			region = zone[:len(zone)-1]
		}
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, r["ID"])

		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         r["Name"],
			ARN:          arn,
			Service:      "EC2",
			ResourceType: "instance",
			Region:       region,
			Role:         r["Role"],
			IsAdmin:      normalizeFlag(r["IsAdminRole?"]),
			CanPrivEsc:   normalizeFlag(r["CanPrivEscToAdmin?"]),
			Properties: buildProperties(map[string]string{
				"InstanceID": r["ID"],
				"Zone":       r["Zone"],
				"State":      r["State"],
				"InternalIP": r["Internal IP"],
				"ExternalIP": r["External IP"],
			}),
		})
	}
	return resources
}

// parseInventoryARNs reads loot/inventory.txt and creates minimal resources from ARNs
// not already known from JSON files.
func parseInventoryARNs(path string, accountID string) []Resource {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var resources []Resource
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "arn:") {
			continue
		}
		service, resourceType := parseARNServiceAndType(line)
		region := extractRegionFromARN(line)
		name := extractNameFromARN(line)
		resources = append(resources, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          line,
			Service:      service,
			ResourceType: resourceType,
			Region:       region,
		})
	}
	return resources
}

// parseAccessKeyIDsFromLoot reads loot/access-keys.txt and returns the key IDs found.
func parseAccessKeyIDsFromLoot(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var keyIDs []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AKIA") || strings.HasPrefix(line, "ASIA") {
			keyIDs = append(keyIDs, line)
		}
	}
	return keyIDs
}

// parseARNServiceAndType extracts the service and resource type from an ARN.
func parseARNServiceAndType(arn string) (service string, resourceType string) {
	parts := strings.SplitN(arn, ":", 7)
	if len(parts) < 6 {
		return "Unknown", "unknown"
	}

	svc := parts[2]
	resource := parts[5]

	// Map AWS service names to display names
	serviceMap := map[string]string{
		"s3":                 "S3",
		"ec2":                "EC2",
		"iam":                "IAM",
		"lambda":             "Lambda",
		"dynamodb":           "DynamoDB",
		"rds":                "RDS",
		"ssm":                "SSM",
		"sns":                "SNS",
		"sqs":                "SQS",
		"ecs":                "ECS",
		"ecr":                "ECR",
		"apprunner":          "AppRunner",
		"codebuild":          "CodeBuild",
		"cloudformation":     "CloudFormation",
		"glue":               "Glue",
		"elasticmapreduce":   "EMR",
		"secretsmanager":     "SecretsManager",
		"elasticloadbalancing": "ELB",
	}

	displayService := svc
	if mapped, ok := serviceMap[svc]; ok {
		displayService = mapped
	}

	// Extract resource type from the resource portion of the ARN
	resourceType = "resource"
	if idx := strings.Index(resource, "/"); idx >= 0 {
		resourceType = resource[:idx]
	} else if idx := strings.Index(resource, ":"); idx >= 0 {
		resourceType = resource[:idx]
	} else {
		resourceType = resource
	}

	return displayService, resourceType
}

// extractRegionFromARN extracts the region from an ARN.
func extractRegionFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 7)
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

// extractNameFromARN extracts a human-readable name from an ARN.
func extractNameFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 7)
	if len(parts) < 6 {
		return arn
	}
	resource := parts[5]
	// For resources with paths (e.g., role/my-role, function:my-func)
	if idx := strings.LastIndex(resource, "/"); idx >= 0 {
		return resource[idx+1:]
	}
	if idx := strings.LastIndex(resource, ":"); idx >= 0 {
		return resource[idx+1:]
	}
	return resource
}

// normalizeFlag normalizes cloudfox boolean flags to consistent values.
func normalizeFlag(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true":
		return "Yes"
	case "no", "false":
		return "No"
	case "skipped", "":
		return ""
	default:
		return value
	}
}

// buildProperties creates a properties map, excluding empty values.
func buildProperties(kvs map[string]string) map[string]string {
	props := make(map[string]string)
	for k, v := range kvs {
		v = strings.TrimSpace(v)
		if v != "" && v != "-" && v != "N/A" {
			props[k] = v
		}
	}
	if len(props) == 0 {
		return nil
	}
	return props
}
