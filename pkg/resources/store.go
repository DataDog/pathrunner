package resources

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager handles cloudfox resource loading, storage, and querying.
type Manager struct {
	mu       sync.RWMutex
	accounts map[string]*AccountResources
}

// NewManager creates a new resources manager.
func NewManager() *Manager {
	return &Manager{
		accounts: make(map[string]*AccountResources),
	}
}

// resourcesDir returns the directory for storing imported resource data.
func resourcesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".pathrunner", "resources")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("could not create resources directory: %w", err)
	}
	return dir, nil
}

// resourcePath returns the file path for a specific account's resource data.
func resourcePath(accountID string) (string, error) {
	dir, err := resourcesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, accountID+".json"), nil
}

// Import imports cloudfox data from a directory path.
// If the path points directly to a profile directory (with json/ or loot/ subdirs),
// it imports that single profile. Otherwise, it scans for profile subdirectories.
// Returns the imported account IDs and any discovered access key IDs.
func (m *Manager) Import(dirPath string, accountIDs []string) ([]string, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If dirPath itself contains cloudfox data, import just that one
	if hasCloudfoxData(dirPath) {
		ar, accessKeyIDs, err := ImportFromDir(dirPath)
		if err != nil {
			return nil, nil, err
		}
		m.mergeAccount(ar)
		if err := m.saveAccount(ar.AccountID); err != nil {
			return nil, nil, fmt.Errorf("imported but failed to persist: %w", err)
		}
		return []string{ar.AccountID}, accessKeyIDs, nil
	}

	// Otherwise, scan for profile subdirectories
	profileDirs, err := FindProfileDirs(dirPath, accountIDs)
	if err != nil {
		return nil, nil, err
	}

	if len(profileDirs) == 0 {
		return nil, nil, fmt.Errorf("no cloudfox data found in %s", dirPath)
	}

	var imported []string
	var allAccessKeyIDs []string
	for accountID, pd := range profileDirs {
		ar, accessKeyIDs, err := ImportFromDir(pd.Path)
		if err != nil {
			return imported, allAccessKeyIDs, fmt.Errorf("failed to import account %s: %w", accountID, err)
		}
		m.mergeAccount(ar)
		if err := m.saveAccount(ar.AccountID); err != nil {
			return imported, allAccessKeyIDs, fmt.Errorf("imported %s but failed to persist: %w", accountID, err)
		}
		imported = append(imported, ar.AccountID)
		allAccessKeyIDs = append(allAccessKeyIDs, accessKeyIDs...)
	}

	return imported, allAccessKeyIDs, nil
}

// mergeAccount merges new import data into existing account resources.
// If the account already has data, resources are merged by ARN and a new
// ImportRecord is appended. If not, the account is stored as-is.
func (m *Manager) mergeAccount(incoming *AccountResources) {
	existing, exists := m.accounts[incoming.AccountID]
	if !exists {
		m.accounts[incoming.AccountID] = incoming
		return
	}

	// Append import records
	existing.Imports = append(existing.Imports, incoming.Imports...)

	// Merge resources: combine existing and incoming, then deduplicate
	combined := append(existing.Resources, incoming.Resources...)
	existing.Resources = deduplicateResources(combined)
}

// IsLoaded returns whether resources are loaded for the given account.
func (m *Manager) IsLoaded(accountID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.accounts[accountID]
	return exists
}

// GetAccount returns the resources for an account, loading from disk if needed.
func (m *Manager) GetAccount(accountID string) (*AccountResources, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ar, exists := m.accounts[accountID]; exists {
		return ar, nil
	}

	ar, err := m.loadAccount(accountID)
	if err != nil {
		return nil, err
	}
	m.accounts[accountID] = ar
	return ar, nil
}

// TryAutoLoad attempts to load resources from disk for the given account ID.
// Returns true if resources were loaded successfully.
func (m *Manager) TryAutoLoad(accountID string) bool {
	if accountID == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.accounts[accountID]; exists {
		return true
	}

	ar, err := m.loadAccount(accountID)
	if err != nil {
		return false
	}
	m.accounts[accountID] = ar
	return true
}

// ListResources returns resources for an account, optionally filtered by service.
func (m *Manager) ListResources(accountID string, serviceFilter string) []Resource {
	ar, err := m.GetAccount(accountID)
	if err != nil {
		return nil
	}

	if serviceFilter == "" {
		return ar.Resources
	}

	var filtered []Resource
	for _, r := range ar.Resources {
		if strings.EqualFold(r.Service, serviceFilter) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// Summary returns resource counts grouped by service and region for an account.
func (m *Manager) Summary(accountID string) []ResourceSummary {
	ar, err := m.GetAccount(accountID)
	if err != nil {
		return nil
	}

	// Count by service+region
	counts := make(map[string]int) // "service:region" -> count
	for _, r := range ar.Resources {
		region := r.Region
		if region == "" {
			region = "global"
		}
		key := r.Service + ":" + region
		counts[key]++
	}

	var summaries []ResourceSummary
	for key, count := range counts {
		parts := strings.SplitN(key, ":", 2)
		summaries = append(summaries, ResourceSummary{
			Service: parts[0],
			Region:  parts[1],
			Count:   count,
		})
	}

	// Sort by service name, then region
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Service != summaries[j].Service {
			return summaries[i].Service < summaries[j].Service
		}
		return summaries[i].Region < summaries[j].Region
	})

	return summaries
}

// Status returns import status for all loaded accounts.
func (m *Manager) Status() []ImportStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var statuses []ImportStatus
	for _, ar := range m.accounts {
		serviceCounts := make(map[string]int)
		for _, r := range ar.Resources {
			serviceCounts[r.Service]++
		}
		statuses = append(statuses, ImportStatus{
			AccountID:     ar.AccountID,
			Imports:       ar.Imports,
			ResourceCount: len(ar.Resources),
			ServiceCounts: serviceCounts,
		})
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].AccountID < statuses[j].AccountID
	})

	return statuses
}

// AvailableServices returns the unique set of services across all resources for an account.
func (m *Manager) AvailableServices(accountID string) []string {
	ar, err := m.GetAccount(accountID)
	if err != nil {
		return nil
	}

	serviceSet := make(map[string]bool)
	for _, r := range ar.Resources {
		serviceSet[r.Service] = true
	}

	var services []string
	for s := range serviceSet {
		services = append(services, s)
	}
	sort.Strings(services)
	return services
}

// OptionMappings maps module option names to resource service/type queries.
var OptionMappings = map[string]OptionResourceMapping{
	"ROLE_ARN":           {Service: "IAM", ResourceType: "role", ReturnField: "arn"},
	"EXECUTION_ROLE_ARN": {Service: "IAM", ResourceType: "role", ReturnField: "arn"},
	"SERVICE_ROLE":       {Service: "IAM", ResourceType: "role", ReturnField: "arn"},
	"INSTANCE_PROFILE":   {Service: "IAM", ResourceType: "instance-profile", ReturnField: "name"},
	"TARGET_RUNTIME_ARN": {Service: "BedrockAgentCore", ResourceType: "runtime", ReturnField: "arn"},
	"FUNCTION_NAME":      {Service: "Lambda", ResourceType: "function", ReturnField: "name"},
	"INSTANCE_ID":        {Service: "EC2", ResourceType: "instance", ReturnField: "name"},
	"BUCKET_NAME":        {Service: "S3", ResourceType: "bucket", ReturnField: "name"},
	"BUCKET":             {Service: "S3", ResourceType: "bucket", ReturnField: "name"},
	"JOB_NAME":           {Service: "Glue", ResourceType: "job", ReturnField: "name"},
	"TABLE_NAME":         {Service: "DynamoDB", ResourceType: "table", ReturnField: "name"},
	"PROJECT_NAME":       {Service: "CodeBuild", ResourceType: "project", ReturnField: "name"},
	"GROUP_NAME":         {Service: "IAM", ResourceType: "group", ReturnField: "name"},
	"USER_NAME":          {Service: "IAM", ResourceType: "user", ReturnField: "name"},
	"TARGET_USER":        {Service: "IAM", ResourceType: "user", ReturnField: "name"},
	"APP_NAME":           {Service: "CodeDeploy", ResourceType: "application", ReturnField: "name"},
	"DEPLOYMENT_GROUP":   {Service: "CodeDeploy", ResourceType: "deployment-group", ReturnField: "name"},
}

// ImportCache imports AWS resources from a cloudfox cached-data account directory.
// accountDir is the full path to the account-specific directory (e.g. ~/.cloudfox/cached-data/aws/123456789012).
// Returns the imported account ID.
func (m *Manager) ImportCache(accountDir string, accountID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ar, err := ImportFromCacheDir(accountDir, accountID)
	if err != nil {
		return "", err
	}
	m.mergeAccount(ar)
	if err := m.saveAccount(ar.AccountID); err != nil {
		return "", fmt.Errorf("imported but failed to persist: %w", err)
	}
	return ar.AccountID, nil
}

// AddDiscoveredResources merges resources learned from module discovery API calls
// into the account's resource set and persists to disk.
func (m *Manager) AddDiscoveredResources(accountID string, newResources []Resource, sourceInfo string) error {
	if accountID == "" || len(newResources) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Set source on all incoming resources
	for i := range newResources {
		newResources[i].Source = "discover"
		newResources[i].AccountID = accountID
	}

	incoming := &AccountResources{
		AccountID: accountID,
		Imports: []ImportRecord{
			{
				SourceType: "discover",
				SourceInfo: sourceInfo,
				ImportedAt: time.Now(),
			},
		},
		Resources: newResources,
	}

	m.mergeAccount(incoming)

	return m.saveAccount(accountID)
}

// FindChoicesForOption queries the resource store for values that match a module option.
// Returns nil if the option name has no known resource mapping.
func (m *Manager) FindChoicesForOption(accountID string, optionName string) []DiscoverySuggestion {
	mapping, exists := OptionMappings[optionName]
	if !exists {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ar, exists := m.accounts[accountID]
	if !exists {
		// Try loading from disk without holding write lock
		m.mu.RUnlock()
		m.mu.Lock()
		loaded, err := m.loadAccount(accountID)
		if err != nil {
			m.mu.Unlock()
			m.mu.RLock()
			return nil
		}
		m.accounts[accountID] = loaded
		ar = loaded
		m.mu.Unlock()
		m.mu.RLock()
	}

	var suggestions []DiscoverySuggestion
	for _, r := range ar.Resources {
		if !strings.EqualFold(r.Service, mapping.Service) {
			continue
		}
		if !strings.EqualFold(r.ResourceType, mapping.ResourceType) {
			continue
		}

		value := r.Name
		if mapping.ReturnField == "arn" && r.ARN != "" {
			value = r.ARN
		}
		if value == "" {
			continue
		}

		// Build a descriptive label similar to discovery labels
		label := r.Name
		if r.IsAdmin == "Yes" {
			label += " [ADMIN]"
		}
		if r.Role != "" {
			label += fmt.Sprintf(" (role: %s)", r.Role)
		}

		source := r.Source
		if source == "" {
			source = "cloudfox"
		}

		suggestions = append(suggestions, DiscoverySuggestion{
			Value:  value,
			Label:  label,
			Source: source,
		})
	}

	return suggestions
}

// ClearAccount removes all resources for a single account from memory and disk.
func (m *Manager) ClearAccount(accountID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.accounts, accountID)

	path, err := resourcePath(accountID)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove resource file for %s: %w", accountID, err)
	}
	return nil
}

// ClearAll removes all resources for every account from memory and disk.
// Returns the number of accounts cleared.
func (m *Manager) ClearAll() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	dir, err := resourcesDir()
	if err != nil {
		return 0, err
	}

	count := len(m.accounts)
	m.accounts = make(map[string]*AccountResources)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return count, nil // memory cleared; disk read failure is non-fatal
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return count, nil
}

// LoadedAccountIDs returns the account IDs currently loaded in memory.
func (m *Manager) LoadedAccountIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.accounts))
	for id := range m.accounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// saveAccount persists account resources to disk.
func (m *Manager) saveAccount(accountID string) error {
	ar, exists := m.accounts[accountID]
	if !exists {
		return fmt.Errorf("no data for account %s", accountID)
	}

	path, err := resourcePath(accountID)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(ar, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal resources: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// loadAccount loads account resources from disk.
func (m *Manager) loadAccount(accountID string) (*AccountResources, error) {
	path, err := resourcePath(accountID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no resource data for account %s: %w", accountID, err)
	}

	var ar AccountResources
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("failed to parse resource data: %w", err)
	}

	return &ar, nil
}
