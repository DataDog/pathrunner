package attacker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

const (
	keyPairName        = "pathrunner-deploy"
	securityGroupName  = "pathrunner-deploy-sg"
	instanceProfileStr = "pathrunner-deploy-profile"
	roleName           = "pathrunner-deploy-role"
	instanceType       = "t3.micro"
)

// DeployEC2Result holds the output of a successful EC2 deployment.
type DeployEC2Result struct {
	InstanceID string
	PublicIP   string
	Region     string
	KeyFile    string
	IsUpdate   bool
}

// UpdateEC2 cross-compiles the pathrunner binary and uploads it to an existing EC2 instance.
// Returns an error if no instance is currently deployed or running.
func UpdateEC2(attackerCfg aws.Config) (*DeployEC2Result, error) {
	state, err := LoadDeployState()
	if err != nil {
		return nil, err
	}

	if state.EC2 == nil {
		return nil, fmt.Errorf("no EC2 deployment found. Use 'attacker infra ec2 create' first")
	}

	ec2Client := ec2.NewFromConfig(attackerCfg, func(o *ec2.Options) {
		o.Region = state.EC2.Region
	})

	running, err := isInstanceRunning(ec2Client, state.EC2.InstanceID)
	if err != nil || !running {
		return nil, fmt.Errorf("instance %s is not running. Use 'attacker infra ec2 create' to deploy a new one", state.EC2.InstanceID)
	}

	binaryPath, err := crossCompile()
	if err != nil {
		return nil, err
	}
	defer os.Remove(binaryPath)

	fmt.Printf("[*] Uploading binary to %s (%s)...\n", state.EC2.InstanceID, state.EC2.PublicIP)

	if err := uploadBinary(binaryPath, state.EC2.KeyFilePath, state.EC2.PublicIP); err != nil {
		return nil, fmt.Errorf("failed to upload binary: %v", err)
	}

	return &DeployEC2Result{
		InstanceID: state.EC2.InstanceID,
		PublicIP:   state.EC2.PublicIP,
		Region:     state.EC2.Region,
		KeyFile:    state.EC2.KeyFilePath,
		IsUpdate:   true,
	}, nil
}

// DeployEC2 creates or updates a pathrunner EC2 instance in the attacker account.
// If an instance already exists, it just uploads the latest binary.
func DeployEC2(attackerCfg aws.Config, region string, operatorPublicIP string) (*DeployEC2Result, error) {
	state, err := LoadDeployState()
	if err != nil {
		return nil, err
	}

	// Cross-compile the binary first (before any AWS calls)
	binaryPath, err := crossCompile()
	if err != nil {
		return nil, err
	}
	defer os.Remove(binaryPath)

	ec2Client := ec2.NewFromConfig(attackerCfg, func(o *ec2.Options) {
		o.Region = region
	})

	// Check if we already have a running instance
	if state.EC2 != nil && state.EC2.Region == region {
		running, err := isInstanceRunning(ec2Client, state.EC2.InstanceID)
		if err == nil && running {
			// Instance exists -- just update the binary
			fmt.Printf("[*] Existing instance found: %s (%s)\n", state.EC2.InstanceID, state.EC2.PublicIP)

			if err := uploadBinary(binaryPath, state.EC2.KeyFilePath, state.EC2.PublicIP); err != nil {
				return nil, fmt.Errorf("failed to upload binary: %v", err)
			}

			return &DeployEC2Result{
				InstanceID: state.EC2.InstanceID,
				PublicIP:   state.EC2.PublicIP,
				Region:     region,
				KeyFile:    state.EC2.KeyFilePath,
				IsUpdate:   true,
			}, nil
		}
		// Instance gone or in wrong state -- clean up stale state and recreate
		fmt.Println("[*] Previous instance no longer available, creating new one...")
		state.EC2 = nil
	}

	// Full creation flow
	iamClient := iam.NewFromConfig(attackerCfg, func(o *iam.Options) {
		o.Region = region
	})

	// 1. Create key pair
	keyFile, err := createKeyPair(ec2Client)
	if err != nil {
		return nil, err
	}

	// 2. Create security group
	sgID, err := createSecurityGroup(ec2Client, operatorPublicIP)
	if err != nil {
		cleanupKeyPair(ec2Client, keyFile)
		return nil, err
	}

	// 3. Create instance profile with SSM permissions
	profileARN, err := createInstanceProfile(iamClient)
	if err != nil {
		// Non-fatal -- SSM is nice to have, not required
		fmt.Printf("[!] Could not create instance profile for SSM: %v\n", err)
		fmt.Println("[!] SSM access will not be available. SSH will still work.")
	}

	// 4. Get latest Amazon Linux 2023 AMI
	amiID, err := getLatestAL2023AMI(attackerCfg, region)
	if err != nil {
		cleanupSecurityGroup(ec2Client, sgID)
		cleanupKeyPair(ec2Client, keyFile)
		return nil, err
	}

	// 5. Launch instance
	fmt.Printf("[*] Launching %s instance...\n", instanceType)
	runInput := &ec2.RunInstancesInput{
		ImageId:      aws.String(amiID),
		InstanceType: ec2types.InstanceType(instanceType),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		KeyName:      aws.String(keyPairName),
		SecurityGroupIds: []string{sgID},
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeInstance,
				Tags: []ec2types.Tag{
					{Key: aws.String("Name"), Value: aws.String("pathrunner-listener")},
					{Key: aws.String("ManagedBy"), Value: aws.String("pathrunner")},
				},
			},
		},
	}

	if profileARN != "" {
		runInput.IamInstanceProfile = &ec2types.IamInstanceProfileSpecification{
			Name: aws.String(instanceProfileStr),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runOutput, err := ec2Client.RunInstances(ctx, runInput)
	if err != nil {
		cleanupSecurityGroup(ec2Client, sgID)
		cleanupKeyPair(ec2Client, keyFile)
		return nil, fmt.Errorf("failed to launch instance: %v", err)
	}

	instanceID := aws.ToString(runOutput.Instances[0].InstanceId)
	fmt.Printf("[*] Launched instance: %s\n", instanceID)

	// 6. Wait for instance to be running
	fmt.Println("[*] Waiting for instance to be ready...")
	publicIP, err := waitForInstance(ec2Client, instanceID)
	if err != nil {
		_ = terminateInstance(ec2Client, instanceID)
		cleanupSecurityGroup(ec2Client, sgID)
		cleanupKeyPair(ec2Client, keyFile)
		return nil, err
	}

	// 7. Save state before SCP (so we can clean up if SCP fails)
	state.EC2 = &EC2DeployState{
		InstanceID:         instanceID,
		Region:             region,
		PublicIP:           publicIP,
		SecurityGroupID:    sgID,
		KeyPairName:        keyPairName,
		KeyFilePath:        keyFile,
		InstanceProfileARN: profileARN,
		RoleName:           roleName,
		ProfileName:        instanceProfileStr,
	}
	if err := SaveDeployState(state); err != nil {
		fmt.Printf("[!] Warning: failed to save deploy state: %v\n", err)
	}

	// 8. Wait a bit for SSH to be ready, then upload binary
	fmt.Println("[*] Waiting for SSH to become available...")
	if err := waitForSSH(keyFile, publicIP); err != nil {
		return nil, fmt.Errorf("SSH not available after waiting: %v", err)
	}

	if err := uploadBinary(binaryPath, keyFile, publicIP); err != nil {
		return nil, fmt.Errorf("failed to upload binary: %v", err)
	}

	return &DeployEC2Result{
		InstanceID: instanceID,
		PublicIP:   publicIP,
		Region:     region,
		KeyFile:    keyFile,
		IsUpdate:   false,
	}, nil
}

// DestroyEC2 tears down the EC2 instance and all associated resources.
func DestroyEC2(attackerCfg aws.Config) error {
	state, err := LoadDeployState()
	if err != nil {
		return err
	}

	// Determine region: prefer state, fall back to config
	region := attackerCfg.Region
	if state.EC2 != nil && state.EC2.Region != "" {
		region = state.EC2.Region
	}
	if region == "" {
		return fmt.Errorf("no region available. Set a region on the attacker identity or use --region on create")
	}

	ec2Client := ec2.NewFromConfig(attackerCfg, func(o *ec2.Options) {
		o.Region = region
	})
	iamClient := iam.NewFromConfig(attackerCfg, func(o *iam.Options) {
		o.Region = region
	})

	// 1. Find ALL pathrunner-managed instances (not just the one in state)
	managedInstances, err := findManagedInstances(ec2Client)
	if err != nil {
		fmt.Printf("[!] Could not search for managed instances: %v\n", err)
		// Fall back to state-tracked instance only
		if state.EC2 != nil {
			managedInstances = []ec2types.Instance{}
		}
	}

	// Also include the state-tracked instance if not already in the list
	if state.EC2 != nil {
		found := false
		for _, inst := range managedInstances {
			if aws.ToString(inst.InstanceId) == state.EC2.InstanceID {
				found = true
				break
			}
		}
		if !found {
			// Try to describe it directly
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			output, descErr := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
				InstanceIds: []string{state.EC2.InstanceID},
			})
			cancel()
			if descErr == nil && len(output.Reservations) > 0 && len(output.Reservations[0].Instances) > 0 {
				managedInstances = append(managedInstances, output.Reservations[0].Instances[0])
			}
		}
	}

	if len(managedInstances) == 0 && state.EC2 == nil {
		return fmt.Errorf("no EC2 deployment found")
	}

	// 2. Terminate all managed instances
	var instanceIDs []string
	for _, inst := range managedInstances {
		instID := aws.ToString(inst.InstanceId)
		instState := string(inst.State.Name)
		if instState == "terminated" || instState == "shutting-down" {
			fmt.Printf("[*] Instance %s already %s, skipping.\n", instID, instState)
			continue
		}
		fmt.Printf("[*] Terminating instance %s (%s) in %s...\n", instID, instState, region)
		instanceIDs = append(instanceIDs, instID)
	}

	if len(instanceIDs) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: instanceIDs,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("failed to terminate instances: %v", err)
		}

		// Wait for at least one to reach shutting-down/terminated
		fmt.Println("[*] Waiting for instance termination...")
		if err := waitForTermination(ec2Client, instanceIDs[0]); err != nil {
			fmt.Printf("[!] Warning: %v\n", err)
		}
	}

	// 3. Clean up shared resources (SG, key pair, instance profile)
	fmt.Printf("[*] Deleting security group %s...\n", securityGroupName)
	cleanupSecurityGroupByName(ec2Client, securityGroupName)

	fmt.Printf("[*] Deleting key pair %s...\n", keyPairName)
	keyFilePath := ""
	if state.EC2 != nil {
		keyFilePath = state.EC2.KeyFilePath
	}
	cleanupKeyPair(ec2Client, keyFilePath)

	fmt.Println("[*] Deleting instance profile and role...")
	cleanupInstanceProfile(iamClient, instanceProfileStr, roleName)

	// 4. Update state
	state.EC2 = nil
	if state.HasAnyDeployedResources() {
		SaveDeployState(state)
	} else {
		RemoveDeployState()
	}

	return nil
}

// findManagedInstances finds all non-terminated EC2 instances tagged with ManagedBy=pathrunner.
func findManagedInstances(client *ec2.Client) ([]ec2types.Instance, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("tag:ManagedBy"),
				Values: []string{"pathrunner"},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"pending", "running", "stopping", "stopped"},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	var instances []ec2types.Instance
	for _, reservation := range output.Reservations {
		instances = append(instances, reservation.Instances...)
	}
	return instances, nil
}

// cleanupSecurityGroupByName deletes a security group by name (best effort).
func cleanupSecurityGroupByName(client *ec2.Client, groupName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Find the SG by name first
	output, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("group-name"), Values: []string{groupName}},
		},
	})
	if err != nil || len(output.SecurityGroups) == 0 {
		return
	}

	for _, sg := range output.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		cleanupSecurityGroup(client, sgID)
	}
}

// GetEC2Status returns the current status of the deployed EC2 instance.
func GetEC2Status(attackerCfg aws.Config) (*EC2DeployState, string, error) {
	state, err := LoadDeployState()
	if err != nil {
		return nil, "", err
	}

	if state.EC2 == nil {
		return nil, "not deployed", nil
	}

	ec2Client := ec2.NewFromConfig(attackerCfg, func(o *ec2.Options) {
		o.Region = state.EC2.Region
	})

	instanceState, err := getInstanceState(ec2Client, state.EC2.InstanceID)
	if err != nil {
		return state.EC2, "unknown", nil
	}

	return state.EC2, instanceState, nil
}

// --- Internal helpers ---

// crossCompile builds pathrunner for linux/amd64.
func crossCompile() (string, error) {
	fmt.Println("[*] Cross-compiling pathrunner for linux/amd64...")

	outputPath := filepath.Join(os.TempDir(), "pathrunner-linux")

	cmd := exec.Command("go", "build", "-o", outputPath, "./cmd/pathrunner/main.go")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cross-compilation failed: %v\n%s", err, string(output))
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		return "", fmt.Errorf("cross-compiled binary not found: %v", err)
	}

	fmt.Printf("[*] Binary compiled: %s (%.1f MB)\n", outputPath, float64(info.Size())/(1024*1024))
	return outputPath, nil
}

// createKeyPair creates an EC2 key pair and saves the private key to ~/.pathrunner/keys/.
func createKeyPair(client *ec2.Client) (string, error) {
	fmt.Printf("[*] Creating key pair: %s\n", keyPairName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	output, err := client.CreateKeyPair(ctx, &ec2.CreateKeyPairInput{
		KeyName: aws.String(keyPairName),
	})
	if err != nil {
		// If key already exists, delete and recreate
		if strings.Contains(err.Error(), "InvalidKeyPair.Duplicate") {
			client.DeleteKeyPair(ctx, &ec2.DeleteKeyPairInput{
				KeyName: aws.String(keyPairName),
			})
			output, err = client.CreateKeyPair(ctx, &ec2.CreateKeyPairInput{
				KeyName: aws.String(keyPairName),
			})
			if err != nil {
				return "", fmt.Errorf("failed to recreate key pair: %v", err)
			}
		} else {
			return "", fmt.Errorf("failed to create key pair: %v", err)
		}
	}

	// Save private key
	homeDir, _ := os.UserHomeDir()
	keyDir := filepath.Join(homeDir, ".pathrunner", "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create key directory: %v", err)
	}

	keyFile := filepath.Join(keyDir, keyPairName+".pem")
	if err := os.WriteFile(keyFile, []byte(aws.ToString(output.KeyMaterial)), 0400); err != nil {
		return "", fmt.Errorf("failed to save key file: %v", err)
	}

	fmt.Printf("[*] Key saved to %s\n", keyFile)
	return keyFile, nil
}

// createSecurityGroup creates a security group for the pathrunner instance.
func createSecurityGroup(client *ec2.Client, operatorIP string) (string, error) {
	fmt.Printf("[*] Creating security group: %s\n", securityGroupName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get default VPC
	vpcOutput, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("isDefault"), Values: []string{"true"}},
		},
	})
	if err != nil || len(vpcOutput.Vpcs) == 0 {
		return "", fmt.Errorf("failed to find default VPC: %v", err)
	}
	vpcID := aws.ToString(vpcOutput.Vpcs[0].VpcId)

	// Check if SG already exists and reuse it
	existingSGs, _ := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("group-name"), Values: []string{securityGroupName}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})

	var sgID string
	if existingSGs != nil && len(existingSGs.SecurityGroups) > 0 {
		sgID = aws.ToString(existingSGs.SecurityGroups[0].GroupId)
		fmt.Printf("[*] Reusing existing security group: %s (%s)\n", securityGroupName, sgID)
	} else {
		sgOutput, err := client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
			GroupName:   aws.String(securityGroupName),
			Description: aws.String("Pathrunner listener - SSH + credential collector + shell listener"),
			VpcId:       aws.String(vpcID),
			TagSpecifications: []ec2types.TagSpecification{
				{
					ResourceType: ec2types.ResourceTypeSecurityGroup,
					Tags: []ec2types.Tag{
						{Key: aws.String("ManagedBy"), Value: aws.String("pathrunner")},
					},
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to create security group: %v", err)
		}
		sgID = aws.ToString(sgOutput.GroupId)
	}

	// Add ingress rules
	sshCIDR := "0.0.0.0/0"
	if operatorIP != "" {
		sshCIDR = operatorIP + "/32"
	}

	_, err = client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String(sshCIDR), Description: aws.String("SSH from operator")}},
			},
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(8443),
				ToPort:     aws.Int32(8443),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0"), Description: aws.String("Credential collector")}},
			},
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(4444),
				ToPort:     aws.Int32(4444),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0"), Description: aws.String("Reverse shell listener")}},
			},
		},
	})
	if err != nil && !strings.Contains(err.Error(), "InvalidPermission.Duplicate") {
		client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(sgID)})
		return "", fmt.Errorf("failed to add security group rules: %v", err)
	}

	fmt.Println("[*] Security group rules:")
	fmt.Printf("    - Inbound 22 (SSH) from %s\n", sshCIDR)
	fmt.Println("    - Inbound 8443 (creds) from 0.0.0.0/0")
	fmt.Println("    - Inbound 4444 (shell) from 0.0.0.0/0")

	return sgID, nil
}

// createInstanceProfile creates an IAM instance profile with SSM permissions.
func createInstanceProfile(client *iam.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create role with EC2 trust policy
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "ec2.amazonaws.com"},
			"Action": "sts:AssumeRole"
		}]
	}`

	_, err := client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(trustPolicy),
		Description:              aws.String("Pathrunner deploy instance role for SSM access"),
		Tags: []iamtypes.Tag{
			{Key: aws.String("ManagedBy"), Value: aws.String("pathrunner")},
		},
	})
	if err != nil && !strings.Contains(err.Error(), "EntityAlreadyExists") {
		return "", fmt.Errorf("failed to create IAM role: %v", err)
	}

	// Attach SSM managed policy
	_, err = client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach SSM policy: %v", err)
	}

	// Create instance profile
	profileOutput, err := client.CreateInstanceProfile(ctx, &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String(instanceProfileStr),
		Tags: []iamtypes.Tag{
			{Key: aws.String("ManagedBy"), Value: aws.String("pathrunner")},
		},
	})
	if err != nil {
		if strings.Contains(err.Error(), "EntityAlreadyExists") {
			// Already exists, get its ARN
			getOutput, getErr := client.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
				InstanceProfileName: aws.String(instanceProfileStr),
			})
			if getErr != nil {
				return "", fmt.Errorf("failed to get existing instance profile: %v", getErr)
			}
			return aws.ToString(getOutput.InstanceProfile.Arn), nil
		}
		return "", fmt.Errorf("failed to create instance profile: %v", err)
	}

	// Add role to instance profile
	_, err = client.AddRoleToInstanceProfile(ctx, &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(instanceProfileStr),
		RoleName:            aws.String(roleName),
	})
	if err != nil && !strings.Contains(err.Error(), "LimitExceeded") {
		return "", fmt.Errorf("failed to add role to instance profile: %v", err)
	}

	// Instance profiles take a few seconds to propagate
	fmt.Println("[*] Waiting for instance profile to propagate...")
	time.Sleep(10 * time.Second)

	return aws.ToString(profileOutput.InstanceProfile.Arn), nil
}

// getLatestAL2023AMI finds the latest Amazon Linux 2023 AMI using SSM parameter store.
func getLatestAL2023AMI(cfg aws.Config, region string) (string, error) {
	ssmClient := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		o.Region = region
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	paramName := "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
	output, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(paramName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get latest AL2023 AMI: %v", err)
	}

	amiID := aws.ToString(output.Parameter.Value)
	fmt.Printf("[*] Using AMI: %s (Amazon Linux 2023)\n", amiID)
	return amiID, nil
}

// waitForInstance waits for an EC2 instance to be running and returns its public IP.
func waitForInstance(client *ec2.Client, instanceID string) (string, error) {
	// Poll every 5 seconds for up to 3 minutes
	for i := 0; i < 36; i++ {
		time.Sleep(5 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: []string{instanceID},
		})
		cancel()

		if err != nil {
			continue
		}

		if len(output.Reservations) == 0 || len(output.Reservations[0].Instances) == 0 {
			continue
		}

		instance := output.Reservations[0].Instances[0]
		state := instance.State.Name

		if state == ec2types.InstanceStateNameRunning {
			publicIP := aws.ToString(instance.PublicIpAddress)
			if publicIP != "" {
				fmt.Printf("[*] Instance ready: %s\n", publicIP)
				return publicIP, nil
			}
		}

		if state == ec2types.InstanceStateNameTerminated || state == ec2types.InstanceStateNameShuttingDown {
			return "", fmt.Errorf("instance entered %s state", state)
		}
	}

	return "", fmt.Errorf("timed out waiting for instance to be ready")
}

// waitForTermination waits for an instance to reach terminated or shutting-down state.
func waitForTermination(client *ec2.Client, instanceID string) error {
	for i := 0; i < 24; i++ {
		time.Sleep(5 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: []string{instanceID},
		})
		cancel()

		if err != nil {
			return fmt.Errorf("failed to check instance state: %v", err)
		}

		if len(output.Reservations) > 0 && len(output.Reservations[0].Instances) > 0 {
			state := output.Reservations[0].Instances[0].State.Name
			if state == ec2types.InstanceStateNameTerminated || state == ec2types.InstanceStateNameShuttingDown {
				return nil
			}
			fmt.Printf("[*] Instance state: %s\n", state)
		}
	}
	return fmt.Errorf("timed out waiting for instance %s to terminate", instanceID)
}

// waitForSSH polls SSH connectivity until the instance accepts connections.
func waitForSSH(keyFile string, publicIP string) error {
	for i := 0; i < 30; i++ {
		cmd := exec.Command("ssh",
			"-i", keyFile,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			fmt.Sprintf("ec2-user@%s", publicIP),
			"echo ready",
		)
		if err := cmd.Run(); err == nil {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("SSH not available after 150 seconds")
}

// uploadBinary copies the pathrunner binary to the EC2 instance via SCP.
func uploadBinary(binaryPath string, keyFile string, publicIP string) error {
	fmt.Println("[*] Uploading pathrunner binary via SCP...")

	cmd := exec.Command("scp",
		"-i", keyFile,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		binaryPath,
		fmt.Sprintf("ec2-user@%s:~/pathrunner", publicIP),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SCP failed: %v\n%s", err, string(output))
	}

	// Move binary to /usr/local/bin so it's on PATH from any directory
	moveCmd := exec.Command("ssh",
		"-i", keyFile,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		fmt.Sprintf("ec2-user@%s", publicIP),
		"sudo mv ~/pathrunner /usr/local/bin/pathrunner && sudo chmod +x /usr/local/bin/pathrunner",
	)
	if moveOutput, err := moveCmd.CombinedOutput(); err != nil {
		fmt.Printf("[!] Failed to move binary to /usr/local/bin: %v\n%s", err, string(moveOutput))
		fmt.Println("[*] Binary available at ~/pathrunner instead.")
	}

	fmt.Println("[*] Binary uploaded successfully.")
	return nil
}

// isInstanceRunning checks if the given instance ID is in the running state.
func isInstanceRunning(client *ec2.Client, instanceID string) (bool, error) {
	state, err := getInstanceState(client, instanceID)
	if err != nil {
		return false, err
	}
	return state == "running", nil
}

// getInstanceState returns the state name of an EC2 instance.
func getInstanceState(client *ec2.Client, instanceID string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return "", err
	}

	if len(output.Reservations) == 0 || len(output.Reservations[0].Instances) == 0 {
		return "not found", nil
	}

	return string(output.Reservations[0].Instances[0].State.Name), nil
}

// terminateInstance terminates an EC2 instance.
func terminateInstance(client *ec2.Client, instanceID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
	})
	return err
}

// cleanupKeyPair deletes an EC2 key pair and its local key file.
func cleanupKeyPair(client *ec2.Client, keyFile string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client.DeleteKeyPair(ctx, &ec2.DeleteKeyPairInput{
		KeyName: aws.String(keyPairName),
	})

	if keyFile != "" {
		os.Remove(keyFile)
	}
}

// cleanupSecurityGroup deletes a security group.
func cleanupSecurityGroup(client *ec2.Client, sgID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(sgID),
	})
}

// cleanupInstanceProfile removes the role from the instance profile, deletes the
// profile, detaches policies from the role, and deletes the role.
func cleanupInstanceProfile(client *iam.Client, profileName string, iamRoleName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Remove role from instance profile
	client.RemoveRoleFromInstanceProfile(ctx, &iam.RemoveRoleFromInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
		RoleName:            aws.String(iamRoleName),
	})

	// Delete instance profile
	client.DeleteInstanceProfile(ctx, &iam.DeleteInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	})

	// Detach SSM policy
	client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName:  aws.String(iamRoleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
	})

	// Delete role
	client.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(iamRoleName),
	})
}

