package unit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/pathrunner/pkg/resources"
)

const cloudfoxFixtureDir = "../fixtures/cloudfox"

func TestResourcesImportFromDir(t *testing.T) {
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	ar, accessKeyIDs, err := resources.ImportFromDir(profileDir)
	if err != nil {
		t.Fatalf("ImportFromDir failed: %v", err)
	}

	if ar.AccountID != "123456789012" {
		t.Errorf("expected account ID 123456789012, got %s", ar.AccountID)
	}

	if len(ar.Imports) != 1 {
		t.Errorf("expected 1 import record, got %d", len(ar.Imports))
	}

	if ar.Imports[0].Profile != "testprofile" {
		t.Errorf("expected profile 'testprofile', got %s", ar.Imports[0].Profile)
	}

	if len(ar.Imports[0].FilesParsed) == 0 {
		t.Error("expected files parsed to be non-empty")
	}

	// Should have resources from multiple files
	if len(ar.Resources) == 0 {
		t.Fatal("expected resources to be non-empty")
	}

	// Check access key IDs from loot
	if len(accessKeyIDs) != 2 {
		t.Errorf("expected 2 access key IDs, got %d", len(accessKeyIDs))
	}
}

func TestResourcesImportFromDir_MissingDir(t *testing.T) {
	_, _, err := resources.ImportFromDir("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestResourcesImportFromDir_WorkloadsParsing(t *testing.T) {
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	ar, _, err := resources.ImportFromDir(profileDir)
	if err != nil {
		t.Fatalf("ImportFromDir failed: %v", err)
	}

	// Find the EC2 instance from workloads
	var ec2Instance *resources.Resource
	var lambdaFunc *resources.Resource
	for i, r := range ar.Resources {
		if r.Name == "test-instance" && r.Service == "EC2" && r.ResourceType == "instance" {
			ec2Instance = &ar.Resources[i]
		}
		if r.Name == "test-function" && r.Service == "Lambda" && r.ResourceType == "function" {
			lambdaFunc = &ar.Resources[i]
		}
	}

	if ec2Instance == nil {
		t.Fatal("expected to find EC2 instance 'test-instance'")
	}
	if ec2Instance.Role != "arn:aws:iam::123456789012:role/test-ec2-role" {
		t.Errorf("unexpected EC2 role: %s", ec2Instance.Role)
	}
	if ec2Instance.Region != "us-east-1" {
		t.Errorf("unexpected EC2 region: %s", ec2Instance.Region)
	}

	if lambdaFunc == nil {
		t.Fatal("expected to find Lambda function 'test-function'")
	}
	if lambdaFunc.IsAdmin != "Yes" {
		t.Errorf("expected Lambda function IsAdmin=Yes, got %s", lambdaFunc.IsAdmin)
	}
	if lambdaFunc.CanPrivEsc != "Yes" {
		t.Errorf("expected Lambda function CanPrivEsc=Yes, got %s", lambdaFunc.CanPrivEsc)
	}
}

func TestResourcesImportFromDir_InstancesSupplementWorkloads(t *testing.T) {
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	ar, _, err := resources.ImportFromDir(profileDir)
	if err != nil {
		t.Fatalf("ImportFromDir failed: %v", err)
	}

	// Find the EC2 instance - should have properties from instances.json merged in
	for _, r := range ar.Resources {
		if r.Name == "test-instance" && r.Service == "EC2" {
			if r.Properties == nil {
				t.Fatal("expected EC2 instance to have properties from instances.json")
			}
			if r.Properties["ExternalIP"] != "54.123.45.67" {
				t.Errorf("expected ExternalIP=54.123.45.67, got %s", r.Properties["ExternalIP"])
			}
			if r.Properties["InternalIP"] != "10.0.1.100" {
				t.Errorf("expected InternalIP=10.0.1.100, got %s", r.Properties["InternalIP"])
			}
			if r.Properties["State"] != "running" {
				t.Errorf("expected State=running, got %s", r.Properties["State"])
			}
			return
		}
	}
	t.Fatal("EC2 instance 'test-instance' not found")
}

func TestResourcesImportFromDir_BucketsParsing(t *testing.T) {
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	ar, _, err := resources.ImportFromDir(profileDir)
	if err != nil {
		t.Fatalf("ImportFromDir failed: %v", err)
	}

	var publicBucket *resources.Resource
	for i, r := range ar.Resources {
		if r.Name == "public-bucket-123456789012" {
			publicBucket = &ar.Resources[i]
			break
		}
	}

	if publicBucket == nil {
		t.Fatal("expected to find bucket 'public-bucket-123456789012'")
	}
	if publicBucket.Public != "Yes" {
		t.Errorf("expected Public=Yes, got %s", publicBucket.Public)
	}
	if publicBucket.ARN != "arn:aws:s3:::public-bucket-123456789012" {
		t.Errorf("expected S3 ARN, got %s", publicBucket.ARN)
	}
}

func TestResourcesImportFromDir_SecretsParsing(t *testing.T) {
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	ar, _, err := resources.ImportFromDir(profileDir)
	if err != nil {
		t.Fatalf("ImportFromDir failed: %v", err)
	}

	var secret *resources.Resource
	for i, r := range ar.Resources {
		if r.Name == "prod-db-credentials" {
			secret = &ar.Resources[i]
			break
		}
	}

	if secret == nil {
		t.Fatal("expected to find secret 'prod-db-credentials'")
	}
	if secret.Service != "SecretsManager" {
		t.Errorf("expected service SecretsManager, got %s", secret.Service)
	}
	if secret.ResourceType != "secret" {
		t.Errorf("expected type secret, got %s", secret.ResourceType)
	}
}

func TestResourcesImportFromDir_Deduplication(t *testing.T) {
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	ar, _, err := resources.ImportFromDir(profileDir)
	if err != nil {
		t.Fatalf("ImportFromDir failed: %v", err)
	}

	// Count resources with the same ARN - should be deduplicated
	arnCounts := make(map[string]int)
	for _, r := range ar.Resources {
		if r.ARN != "" {
			arnCounts[r.ARN]++
		}
	}

	for arn, count := range arnCounts {
		if count > 1 {
			t.Errorf("ARN %s appears %d times (should be deduplicated)", arn, count)
		}
	}
}

func TestFindProfileDirs(t *testing.T) {
	dirs, err := resources.FindProfileDirs(cloudfoxFixtureDir, nil)
	if err != nil {
		t.Fatalf("FindProfileDirs failed: %v", err)
	}

	if len(dirs) != 1 {
		t.Fatalf("expected 1 profile dir, got %d", len(dirs))
	}

	pd, ok := dirs["123456789012"]
	if !ok {
		t.Fatal("expected to find account 123456789012")
	}
	if pd.Profile != "testprofile" {
		t.Errorf("expected profile 'testprofile', got %s", pd.Profile)
	}
	if pd.AccountID != "123456789012" {
		t.Errorf("expected account ID '123456789012', got %s", pd.AccountID)
	}
}

func TestFindProfileDirs_WithFilter(t *testing.T) {
	dirs, err := resources.FindProfileDirs(cloudfoxFixtureDir, []string{"999999999999"})
	if err != nil {
		t.Fatalf("FindProfileDirs failed: %v", err)
	}

	if len(dirs) != 0 {
		t.Errorf("expected 0 dirs with non-matching filter, got %d", len(dirs))
	}
}

func TestManagerImportAndQuery(t *testing.T) {
	m := resources.NewManager()
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")

	imported, _, err := m.Import(profileDir, nil)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	if len(imported) != 1 || imported[0] != "123456789012" {
		t.Errorf("unexpected imported accounts: %v", imported)
	}

	if !m.IsLoaded("123456789012") {
		t.Error("expected account to be loaded")
	}

	// Test ListResources
	allResources := m.ListResources("123456789012", "")
	if len(allResources) == 0 {
		t.Error("expected resources to be non-empty")
	}

	// Test service filter
	ec2Resources := m.ListResources("123456789012", "EC2")
	for _, r := range ec2Resources {
		if r.Service != "EC2" {
			t.Errorf("expected all resources to be EC2, got %s", r.Service)
		}
	}

	lambdaResources := m.ListResources("123456789012", "Lambda")
	for _, r := range lambdaResources {
		if r.Service != "Lambda" {
			t.Errorf("expected all resources to be Lambda, got %s", r.Service)
		}
	}

	// Test Summary
	summaries := m.Summary("123456789012")
	if len(summaries) == 0 {
		t.Error("expected summaries to be non-empty")
	}

	// Test Status
	statuses := m.Status()
	if len(statuses) != 1 {
		t.Errorf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].AccountID != "123456789012" {
		t.Errorf("expected account 123456789012, got %s", statuses[0].AccountID)
	}
	if statuses[0].ResourceCount == 0 {
		t.Error("expected resource count > 0")
	}
}

func TestManagerPersistence(t *testing.T) {
	// Set up temp HOME for persistence
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Import
	m1 := resources.NewManager()
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	_, _, err := m1.Import(profileDir, nil)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	originalCount := len(m1.ListResources("123456789012", ""))

	// Verify file was persisted
	persistPath := filepath.Join(tmpDir, ".pathrunner", "resources", "123456789012.json")
	if _, err := os.Stat(persistPath); os.IsNotExist(err) {
		t.Fatal("expected persisted file to exist")
	}

	// Load in a new manager
	m2 := resources.NewManager()
	if m2.IsLoaded("123456789012") {
		t.Error("expected new manager to not have data loaded")
	}

	loaded := m2.TryAutoLoad("123456789012")
	if !loaded {
		t.Fatal("expected TryAutoLoad to succeed")
	}

	loadedResources := m2.ListResources("123456789012", "")
	if len(loadedResources) != originalCount {
		t.Errorf("expected %d resources after load, got %d", originalCount, len(loadedResources))
	}
}

func TestManagerMultiImportMerge(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	m := resources.NewManager()
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")

	// Import twice
	_, _, err := m.Import(profileDir, nil)
	if err != nil {
		t.Fatalf("First import failed: %v", err)
	}
	countAfterFirst := len(m.ListResources("123456789012", ""))

	_, _, err = m.Import(profileDir, nil)
	if err != nil {
		t.Fatalf("Second import failed: %v", err)
	}
	countAfterSecond := len(m.ListResources("123456789012", ""))

	// Resource count should not double since deduplication should merge by ARN
	if countAfterSecond != countAfterFirst {
		t.Errorf("expected same count after re-import (dedup), got %d vs %d", countAfterFirst, countAfterSecond)
	}

	// Should have 2 import records
	ar, err := m.GetAccount("123456789012")
	if err != nil {
		t.Fatalf("GetAccount failed: %v", err)
	}
	if len(ar.Imports) != 2 {
		t.Errorf("expected 2 import records, got %d", len(ar.Imports))
	}
}

func TestManagerAvailableServices(t *testing.T) {
	m := resources.NewManager()
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	_, _, err := m.Import(profileDir, nil)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	services := m.AvailableServices("123456789012")
	if len(services) == 0 {
		t.Error("expected services to be non-empty")
	}

	// Should include at least EC2, Lambda, IAM, S3
	serviceSet := make(map[string]bool)
	for _, s := range services {
		serviceSet[s] = true
	}
	for _, expected := range []string{"EC2", "Lambda", "IAM", "S3"} {
		if !serviceSet[expected] {
			t.Errorf("expected service %s in available services", expected)
		}
	}
}

func TestFormatSummaryTable(t *testing.T) {
	summaries := []resources.ResourceSummary{
		{Service: "EC2", Region: "us-east-1", Count: 5},
		{Service: "EC2", Region: "us-west-2", Count: 3},
		{Service: "Lambda", Region: "us-east-1", Count: 10},
	}

	headers, rows := resources.FormatSummaryTable(summaries)
	if headers == nil {
		t.Fatal("expected headers to be non-nil")
	}
	if len(rows) == 0 {
		t.Fatal("expected rows to be non-empty")
	}

	// Should have header: Service, us-east-1, us-west-2, Total
	if headers[0] != "Service" {
		t.Errorf("expected first header to be 'Service', got %s", headers[0])
	}
	if headers[len(headers)-1] != "Total" {
		t.Errorf("expected last header to be 'Total', got %s", headers[len(headers)-1])
	}
}

func TestFormatResourceTable(t *testing.T) {
	resourceList := []resources.Resource{
		{Service: "EC2", Name: "test", Region: "us-east-1", Role: "arn:aws:iam::123:role/r", IsAdmin: "No"},
	}

	headers, rows := resources.FormatResourceTable(resourceList)
	if len(headers) == 0 {
		t.Fatal("expected headers")
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
}

func TestFormatStatusReport_Empty(t *testing.T) {
	report := resources.FormatStatusReport(nil)
	if report == "" {
		t.Error("expected non-empty report for nil statuses")
	}
}

func TestAccountResourcesSerialization(t *testing.T) {
	profileDir := filepath.Join(cloudfoxFixtureDir, "testprofile-123456789012")
	ar, _, err := resources.ImportFromDir(profileDir)
	if err != nil {
		t.Fatalf("ImportFromDir failed: %v", err)
	}

	// Serialize and deserialize
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var loaded resources.AccountResources
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if loaded.AccountID != ar.AccountID {
		t.Errorf("account ID mismatch: %s vs %s", loaded.AccountID, ar.AccountID)
	}
	if len(loaded.Resources) != len(ar.Resources) {
		t.Errorf("resource count mismatch: %d vs %d", len(loaded.Resources), len(ar.Resources))
	}
}
