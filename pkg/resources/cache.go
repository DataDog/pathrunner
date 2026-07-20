package resources

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	apprunnerTypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	emrTypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	secretsmanagertypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func init() {
	// Register every concrete type that cloudfox stores as interface{} inside cacheEntry.
	// These registrations must match the gob.Register calls in cloudfox's aws/sdk/ packages
	// so that the decoder can resolve type names from the encoded stream.
	gob.Register([]iamtypes.Role{})
	gob.Register([]iamtypes.User{})
	gob.Register([]iamtypes.AccessKeyMetadata{})
	gob.Register([]iamtypes.InstanceProfile{})
	gob.Register(iamtypes.InstanceProfile{})
	gob.Register([]iamtypes.EvaluationResult{})
	gob.Register([]lambdatypes.FunctionConfiguration{})
	gob.Register([]ec2types.Instance{})
	gob.Register([]ec2types.NetworkInterface{})
	gob.Register([]ec2types.Snapshot{})
	gob.Register([]ec2types.Volume{})
	gob.Register([]ec2types.Image{})
	gob.Register([]ec2types.VpcEndpoint{})
	gob.Register([]s3types.Bucket{})
	gob.Register(s3types.Bucket{})
	gob.Register(&s3types.PublicAccessBlockConfiguration{})
	gob.Register([]secretsmanagertypes.SecretListEntry{})
	gob.Register([]cloudformationtypes.Stack{})
	gob.Register([]cloudformationtypes.StackSummary{})
	gob.Register([]apprunnerTypes.ServiceSummary{})
	gob.Register(apprunnerTypes.Service{})
	gob.Register([]emrTypes.ClusterSummary{})
	gob.Register([]gluetypes.Database{})
	gob.Register(gluetypes.Job{})
	gob.Register([]gluetypes.Table{})
	gob.Register(gluetypes.DevEndpoint{})
	gob.Register([]ssmtypes.ParameterMetadata{})
	gob.Register([]string{})
}

// cacheEntry mirrors cloudfox's internal.cacheEntry. Field names must match exactly for gob.
type cacheEntry struct {
	Value interface{}
	Exp   int64
}

// DefaultCloudfoxCacheDir returns ~/.cloudfox/cached-data/aws if it exists.
func DefaultCloudfoxCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".cloudfox", "cached-data", "aws")
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir
	}
	return ""
}

// ListCacheAccounts returns sorted account IDs found in the cached-data directory.
func ListCacheAccounts(baseDir string) ([]string, error) {
	if baseDir == "" {
		baseDir = DefaultCloudfoxCacheDir()
	}
	if baseDir == "" {
		return nil, fmt.Errorf("could not find cloudfox cached-data directory (~/.cloudfox/cached-data/aws/)")
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cached-data directory %s: %w", baseDir, err)
	}

	var accounts []string
	for _, entry := range entries {
		if entry.IsDir() && accountIDPattern.MatchString(entry.Name()) {
			accounts = append(accounts, entry.Name())
		}
	}
	sort.Strings(accounts)
	return accounts, nil
}

// ImportFromCacheDir decodes all recognized gob files in a cloudfox cached-data account
// directory and returns the aggregated resources.
func ImportFromCacheDir(accountDir string, accountID string) (*AccountResources, error) {
	entries, err := os.ReadDir(accountDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read account cache directory %s: %w", accountDir, err)
	}

	var allResources []Resource
	var filesParsed []string

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".gob" {
			continue
		}

		filename := entry.Name()
		service, operation, region := parseCacheFilename(filename, accountID)
		if service == "" || operation == "" {
			continue
		}

		decoded, ok := decodeCacheFile(filepath.Join(accountDir, filename), service, operation, region, accountID)
		if !ok || len(decoded) == 0 {
			continue
		}

		allResources = append(allResources, decoded...)
		filesParsed = append(filesParsed, filename)
	}

	return &AccountResources{
		AccountID: accountID,
		Imports: []ImportRecord{
			{
				SourceType:  "cloudfox-cache",
				SourceDir:   accountDir,
				ImportedAt:  time.Now(),
				FilesParsed: filesParsed,
			},
		},
		Resources: deduplicateResources(allResources),
	}, nil
}

// parseCacheFilename extracts service, operation, and region from a cache filename.
// Expected format: {accountID}-{service}-{Operation}[-{region}].gob
func parseCacheFilename(filename, accountID string) (service, operation, region string) {
	base := strings.TrimSuffix(filepath.Base(filename), ".gob")
	prefix := accountID + "-"
	if !strings.HasPrefix(base, prefix) {
		return "", "", ""
	}

	// Split into at most 3 parts: service, Operation, remainder
	parts := strings.SplitN(base[len(prefix):], "-", 3)
	if len(parts) < 2 {
		return "", "", ""
	}

	service = parts[0]
	operation = parts[1]
	if len(parts) > 2 {
		region = parts[2]
	}
	return
}

// decodeCacheFile opens a single gob file and converts its contents to Resources.
// Returns nil, false for unrecognized operations or decode errors.
func decodeCacheFile(filePath, service, operation, region, accountID string) ([]Resource, bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var entry cacheEntry
	if err := gob.NewDecoder(f).Decode(&entry); err != nil {
		return nil, false
	}

	switch service + "-" + operation {
	case "iam-ListRoles":
		roles, ok := entry.Value.([]iamtypes.Role)
		if !ok {
			return nil, false
		}
		return convertIAMRoles(roles, accountID), true

	case "iam-ListUsers":
		users, ok := entry.Value.([]iamtypes.User)
		if !ok {
			return nil, false
		}
		return convertIAMUsers(users, accountID), true

	case "iam-ListInstanceProfiles":
		profiles, ok := entry.Value.([]iamtypes.InstanceProfile)
		if !ok {
			return nil, false
		}
		return convertInstanceProfiles(profiles, accountID), true

	case "lambda-ListFunctions":
		functions, ok := entry.Value.([]lambdatypes.FunctionConfiguration)
		if !ok {
			return nil, false
		}
		return convertLambdaFunctions(functions, accountID, region), true

	case "ec2-DescribeInstances":
		instances, ok := entry.Value.([]ec2types.Instance)
		if !ok {
			return nil, false
		}
		return convertEC2Instances(instances, accountID, region), true

	case "s3-ListBuckets":
		buckets, ok := entry.Value.([]s3types.Bucket)
		if !ok {
			return nil, false
		}
		return convertS3Buckets(buckets, accountID), true

	case "secretsmanager-ListSecrets":
		secrets, ok := entry.Value.([]secretsmanagertypes.SecretListEntry)
		if !ok {
			return nil, false
		}
		return convertSecrets(secrets, accountID, region), true

	case "ecs-ListClusters":
		// cloudfox caches cluster ARNs as []string
		clusterARNs, ok := entry.Value.([]string)
		if !ok {
			return nil, false
		}
		return convertECSClusters(clusterARNs, accountID, region), true

	case "cloudformation-ListStacks":
		stacks, ok := entry.Value.([]cloudformationtypes.StackSummary)
		if !ok {
			return nil, false
		}
		return convertCloudFormationStacks(stacks, accountID, region), true

	case "dynamodb-ListTables":
		// cloudfox caches DynamoDB table names as []string
		tableNames, ok := entry.Value.([]string)
		if !ok {
			return nil, false
		}
		return convertDynamoDBTables(tableNames, accountID, region), true

	case "apprunner-ListServices":
		services, ok := entry.Value.([]apprunnerTypes.ServiceSummary)
		if !ok {
			return nil, false
		}
		return convertAppRunnerServices(services, accountID, region), true

	case "emr-ListClusters":
		clusters, ok := entry.Value.([]emrTypes.ClusterSummary)
		if !ok {
			return nil, false
		}
		return convertEMRClusters(clusters, accountID, region), true

	case "glue-GetDatabases":
		databases, ok := entry.Value.([]gluetypes.Database)
		if !ok {
			return nil, false
		}
		return convertGlueDatabases(databases, accountID, region), true

	case "glue-ListJobs":
		// cloudfox caches job names as []string
		jobNames, ok := entry.Value.([]string)
		if !ok {
			return nil, false
		}
		return convertGlueJobs(jobNames, accountID, region), true

	case "glue-ListDevEndpoints":
		// cloudfox caches dev endpoint names as []string
		endpointNames, ok := entry.Value.([]string)
		if !ok {
			return nil, false
		}
		return convertGlueDevEndpoints(endpointNames, accountID, region), true

	case "ssm-DescribeParameters":
		params, ok := entry.Value.([]ssmtypes.ParameterMetadata)
		if !ok {
			return nil, false
		}
		return convertSSMParameters(params, accountID, region), true

	case "ec2-DescribeSnapshots":
		snapshots, ok := entry.Value.([]ec2types.Snapshot)
		if !ok {
			return nil, false
		}
		return convertEC2Snapshots(snapshots, accountID, region), true

	case "ec2-DescribeVolumes":
		volumes, ok := entry.Value.([]ec2types.Volume)
		if !ok {
			return nil, false
		}
		return convertEC2Volumes(volumes, accountID, region), true

	case "ec2-DescribeImages":
		images, ok := entry.Value.([]ec2types.Image)
		if !ok {
			return nil, false
		}
		return convertEC2Images(images, accountID, region), true
	}

	return nil, false
}

func convertIAMRoles(roles []iamtypes.Role, accountID string) []Resource {
	out := make([]Resource, 0, len(roles))
	for _, role := range roles {
		if role.Arn == nil || role.RoleName == nil {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *role.RoleName,
			ARN:          *role.Arn,
			Service:      "IAM",
			ResourceType: "role",
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertIAMUsers(users []iamtypes.User, accountID string) []Resource {
	out := make([]Resource, 0, len(users))
	for _, user := range users {
		if user.Arn == nil || user.UserName == nil {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *user.UserName,
			ARN:          *user.Arn,
			Service:      "IAM",
			ResourceType: "user",
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertInstanceProfiles(profiles []iamtypes.InstanceProfile, accountID string) []Resource {
	out := make([]Resource, 0, len(profiles))
	for _, profile := range profiles {
		if profile.Arn == nil || profile.InstanceProfileName == nil {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *profile.InstanceProfileName,
			ARN:          *profile.Arn,
			Service:      "IAM",
			ResourceType: "instance-profile",
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertLambdaFunctions(functions []lambdatypes.FunctionConfiguration, accountID, region string) []Resource {
	out := make([]Resource, 0, len(functions))
	for _, fn := range functions {
		if fn.FunctionArn == nil || fn.FunctionName == nil {
			continue
		}
		fnRegion := region
		if fnRegion == "" {
			fnRegion = extractRegionFromARN(*fn.FunctionArn)
		}
		r := Resource{
			AccountID:    accountID,
			Name:         *fn.FunctionName,
			ARN:          *fn.FunctionArn,
			Service:      "Lambda",
			ResourceType: "function",
			Region:       fnRegion,
			Source:       "cloudfox-cache",
		}
		if fn.Role != nil {
			r.Role = *fn.Role
		}
		out = append(out, r)
	}
	return out
}

func convertEC2Instances(instances []ec2types.Instance, accountID, region string) []Resource {
	out := make([]Resource, 0, len(instances))
	for _, inst := range instances {
		if inst.InstanceId == nil {
			continue
		}
		name := *inst.InstanceId
		for _, tag := range inst.Tags {
			if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
				name = *tag.Value
				break
			}
		}
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, *inst.InstanceId)

		iamProfile := ""
		if inst.IamInstanceProfile != nil && inst.IamInstanceProfile.Arn != nil {
			iamProfile = *inst.IamInstanceProfile.Arn
		}

		state := ""
		if inst.State != nil {
			state = string(inst.State.Name)
		}

		out = append(out, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          arn,
			Service:      "EC2",
			ResourceType: "instance",
			Region:       region,
			Role:         iamProfile,
			Source:       "cloudfox-cache",
			Properties: buildProperties(map[string]string{
				"InstanceID": *inst.InstanceId,
				"State":      state,
			}),
		})
	}
	return out
}

func convertS3Buckets(buckets []s3types.Bucket, accountID string) []Resource {
	out := make([]Resource, 0, len(buckets))
	for _, bucket := range buckets {
		if bucket.Name == nil {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *bucket.Name,
			ARN:          "arn:aws:s3:::" + *bucket.Name,
			Service:      "S3",
			ResourceType: "bucket",
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertSecrets(secrets []secretsmanagertypes.SecretListEntry, accountID, region string) []Resource {
	out := make([]Resource, 0, len(secrets))
	for _, secret := range secrets {
		if secret.Name == nil {
			continue
		}
		arn := ""
		if secret.ARN != nil {
			arn = *secret.ARN
		}
		secretRegion := region
		if secretRegion == "" && arn != "" {
			secretRegion = extractRegionFromARN(arn)
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *secret.Name,
			ARN:          arn,
			Service:      "SecretsManager",
			ResourceType: "secret",
			Region:       secretRegion,
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertECSClusters(clusterARNs []string, accountID, region string) []Resource {
	out := make([]Resource, 0, len(clusterARNs))
	for _, arn := range clusterARNs {
		if arn == "" {
			continue
		}
		clusterRegion := region
		if clusterRegion == "" {
			clusterRegion = extractRegionFromARN(arn)
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         extractNameFromARN(arn),
			ARN:          arn,
			Service:      "ECS",
			ResourceType: "cluster",
			Region:       clusterRegion,
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertCloudFormationStacks(stacks []cloudformationtypes.StackSummary, accountID, region string) []Resource {
	out := make([]Resource, 0, len(stacks))
	for _, stack := range stacks {
		if stack.StackName == nil {
			continue
		}
		arn := ""
		if stack.StackId != nil {
			arn = *stack.StackId
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *stack.StackName,
			ARN:          arn,
			Service:      "CloudFormation",
			ResourceType: "stack",
			Region:       region,
			Source:       "cloudfox-cache",
			Properties: buildProperties(map[string]string{
				"Status": string(stack.StackStatus),
			}),
		})
	}
	return out
}

func convertDynamoDBTables(tableNames []string, accountID, region string) []Resource {
	out := make([]Resource, 0, len(tableNames))
	for _, name := range tableNames {
		if name == "" {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", region, accountID, name),
			Service:      "DynamoDB",
			ResourceType: "table",
			Region:       region,
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertAppRunnerServices(services []apprunnerTypes.ServiceSummary, accountID, region string) []Resource {
	out := make([]Resource, 0, len(services))
	for _, svc := range services {
		if svc.ServiceName == nil {
			continue
		}
		arn := ""
		if svc.ServiceArn != nil {
			arn = *svc.ServiceArn
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *svc.ServiceName,
			ARN:          arn,
			Service:      "AppRunner",
			ResourceType: "service",
			Region:       region,
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertEMRClusters(clusters []emrTypes.ClusterSummary, accountID, region string) []Resource {
	out := make([]Resource, 0, len(clusters))
	for _, cluster := range clusters {
		if cluster.Name == nil || cluster.Id == nil {
			continue
		}
		arn := fmt.Sprintf("arn:aws:elasticmapreduce:%s:%s:cluster/%s", region, accountID, *cluster.Id)
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *cluster.Name,
			ARN:          arn,
			Service:      "EMR",
			ResourceType: "cluster",
			Region:       region,
			Source:       "cloudfox-cache",
			Properties: buildProperties(map[string]string{
				"ClusterID": *cluster.Id,
				"Status":    string(cluster.Status.State),
			}),
		})
	}
	return out
}

func convertGlueDatabases(databases []gluetypes.Database, accountID, region string) []Resource {
	out := make([]Resource, 0, len(databases))
	for _, db := range databases {
		if db.Name == nil {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *db.Name,
			ARN:          fmt.Sprintf("arn:aws:glue:%s:%s:database/%s", region, accountID, *db.Name),
			Service:      "Glue",
			ResourceType: "database",
			Region:       region,
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertGlueJobs(jobNames []string, accountID, region string) []Resource {
	out := make([]Resource, 0, len(jobNames))
	for _, name := range jobNames {
		if name == "" {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, accountID, name),
			Service:      "Glue",
			ResourceType: "job",
			Region:       region,
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertGlueDevEndpoints(endpointNames []string, accountID, region string) []Resource {
	out := make([]Resource, 0, len(endpointNames))
	for _, name := range endpointNames {
		if name == "" {
			continue
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          fmt.Sprintf("arn:aws:glue:%s:%s:devEndpoint/%s", region, accountID, name),
			Service:      "Glue",
			ResourceType: "dev-endpoint",
			Region:       region,
			Source:       "cloudfox-cache",
		})
	}
	return out
}

func convertSSMParameters(params []ssmtypes.ParameterMetadata, accountID, region string) []Resource {
	out := make([]Resource, 0, len(params))
	for _, param := range params {
		if param.Name == nil {
			continue
		}
		arn := ""
		if param.ARN != nil {
			arn = *param.ARN
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         *param.Name,
			ARN:          arn,
			Service:      "SSM",
			ResourceType: "parameter",
			Region:       region,
			Source:       "cloudfox-cache",
			Properties: buildProperties(map[string]string{
				"Type": string(param.Type),
			}),
		})
	}
	return out
}

func convertEC2Snapshots(snapshots []ec2types.Snapshot, accountID, region string) []Resource {
	out := make([]Resource, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.SnapshotId == nil {
			continue
		}
		name := *snapshot.SnapshotId
		for _, tag := range snapshot.Tags {
			if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
				name = *tag.Value
				break
			}
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          fmt.Sprintf("arn:aws:ec2:%s::snapshot/%s", region, *snapshot.SnapshotId),
			Service:      "EC2",
			ResourceType: "snapshot",
			Region:       region,
			Source:       "cloudfox-cache",
			Properties: buildProperties(map[string]string{
				"SnapshotID": *snapshot.SnapshotId,
			}),
		})
	}
	return out
}

func convertEC2Volumes(volumes []ec2types.Volume, accountID, region string) []Resource {
	out := make([]Resource, 0, len(volumes))
	for _, volume := range volumes {
		if volume.VolumeId == nil {
			continue
		}
		name := *volume.VolumeId
		for _, tag := range volume.Tags {
			if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
				name = *tag.Value
				break
			}
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", region, accountID, *volume.VolumeId),
			Service:      "EC2",
			ResourceType: "volume",
			Region:       region,
			Source:       "cloudfox-cache",
			Properties: buildProperties(map[string]string{
				"VolumeID": *volume.VolumeId,
				"State":    string(volume.State),
			}),
		})
	}
	return out
}

func convertEC2Images(images []ec2types.Image, accountID, region string) []Resource {
	out := make([]Resource, 0, len(images))
	for _, image := range images {
		if image.ImageId == nil {
			continue
		}
		name := *image.ImageId
		if image.Name != nil && *image.Name != "" {
			name = *image.Name
		}
		out = append(out, Resource{
			AccountID:    accountID,
			Name:         name,
			ARN:          fmt.Sprintf("arn:aws:ec2:%s::image/%s", region, *image.ImageId),
			Service:      "EC2",
			ResourceType: "image",
			Region:       region,
			Source:       "cloudfox-cache",
			Properties: buildProperties(map[string]string{
				"ImageID": *image.ImageId,
			}),
		})
	}
	return out
}
