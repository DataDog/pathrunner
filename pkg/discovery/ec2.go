package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// DiscoverSubnets lists VPC subnets available in the current region.
func DiscoverSubnets(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := ec2.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := client.DescribeSubnets(listCtx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("SUBNET_ID", "ec2:DescribeSubnets", err))
		}
		return nil, fmt.Errorf("failed to describe subnets: %v", err)
	}

	var choices []modules.DiscoveryChoice
	for _, subnet := range result.Subnets {
		subnetID := aws.ToString(subnet.SubnetId)
		vpcID := aws.ToString(subnet.VpcId)
		az := aws.ToString(subnet.AvailabilityZone)
		cidr := aws.ToString(subnet.CidrBlock)

		// Build label
		name := getEC2TagValue(subnet.Tags, "Name")
		label := subnetID
		if name != "" {
			label = fmt.Sprintf("%s (%s)", name, subnetID)
		}
		label += fmt.Sprintf(" [%s, %s, %s]", vpcID, az, cidr)
		if aws.ToBool(subnet.DefaultForAz) {
			label += " [default]"
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: subnetID,
			Label: label,
			Metadata: map[string]string{
				"vpc_id":            vpcID,
				"availability_zone": az,
				"cidr_block":        cidr,
				"default":           fmt.Sprintf("%t", aws.ToBool(subnet.DefaultForAz)),
			},
		})
	}

	return choices, nil
}

// DiscoverSecurityGroups lists security groups available in the current region.
func DiscoverSecurityGroups(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := ec2.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allGroups []modules.DiscoveryChoice
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("SECURITY_GROUP_ID", "ec2:DescribeSecurityGroups", err))
			}
			return nil, fmt.Errorf("failed to describe security groups: %v", err)
		}

		for _, sg := range page.SecurityGroups {
			sgID := aws.ToString(sg.GroupId)
			sgName := aws.ToString(sg.GroupName)
			vpcID := aws.ToString(sg.VpcId)
			desc := aws.ToString(sg.Description)

			// Build label
			var parts []string
			parts = append(parts, sgName)
			parts = append(parts, fmt.Sprintf("(%s)", sgID))
			parts = append(parts, fmt.Sprintf("[%s]", vpcID))
			if desc != "" && desc != sgName {
				// Truncate long descriptions
				if len(desc) > 50 {
					desc = desc[:47] + "..."
				}
				parts = append(parts, fmt.Sprintf("- %s", desc))
			}

			allGroups = append(allGroups, modules.DiscoveryChoice{
				Value: sgID,
				Label: strings.Join(parts, " "),
				Metadata: map[string]string{
					"group_name":  sgName,
					"vpc_id":      vpcID,
					"description": aws.ToString(sg.Description),
				},
			})
		}
	}

	return allGroups, nil
}

// DiscoverEC2InstancesWithProfiles lists running EC2 instances that have an IAM
// instance profile attached. Results include the instance ID, public IP, and
// profile ARN so the caller can assess privilege escalation potential.
func DiscoverEC2InstancesWithProfiles(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := ec2.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
		},
	}

	var choices []modules.DiscoveryChoice
	paginator := ec2.NewDescribeInstancesPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("INSTANCE_ID", "ec2:DescribeInstances", err))
			}
			return nil, fmt.Errorf("failed to describe instances: %v", err)
		}

		for _, reservation := range page.Reservations {
			for _, inst := range reservation.Instances {
				instanceID := aws.ToString(inst.InstanceId)

				// Only include instances with an IAM instance profile attached.
				if inst.IamInstanceProfile == nil {
					continue
				}
				profileARN := aws.ToString(inst.IamInstanceProfile.Arn)
				publicIP := aws.ToString(inst.PublicIpAddress)

				name := getEC2TagValue(inst.Tags, "Name")
				label := instanceID
				if name != "" {
					label = fmt.Sprintf("%s (%s)", name, instanceID)
				}
				if publicIP != "" {
					label += fmt.Sprintf(" [%s]", publicIP)
				}
				label += fmt.Sprintf(" profile: %s", profileARN)

				choices = append(choices, modules.DiscoveryChoice{
					Value: instanceID,
					Label: label,
					Metadata: map[string]string{
						"public_ip":           publicIP,
						"instance_profile_arn": profileARN,
						"instance_type":       string(inst.InstanceType),
					},
				})
			}
		}
	}

	if len(choices) == 0 {
		return nil, fmt.Errorf("no running EC2 instances with IAM instance profiles found")
	}

	return choices, nil
}

// DiscoverEC2Instances lists EC2 instances that are running or stopped.
// Both states are valid targets for ec2-002 (ModifyInstanceAttribute requires
// the instance to be stopped, but if it's running the module will stop it first).
func DiscoverEC2Instances(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := ec2.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var choices []modules.DiscoveryChoice
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running", "stopped"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(listCtx)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("INSTANCE_ID", "ec2:DescribeInstances", err))
			}
			return nil, fmt.Errorf("failed to describe instances: %v", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				instanceID := aws.ToString(instance.InstanceId)
				state := string(instance.State.Name)
				instanceType := string(instance.InstanceType)

				// Build a human-readable label.
				name := getEC2TagValue(instance.Tags, "Name")
				label := instanceID
				if name != "" {
					label = fmt.Sprintf("%s (%s)", name, instanceID)
				}
				label += fmt.Sprintf(" [%s, %s]", instanceType, state)

				profileArn := ""
				if instance.IamInstanceProfile != nil {
					profileArn = aws.ToString(instance.IamInstanceProfile.Arn)
					label += fmt.Sprintf(" [profile: %s]", profileArn)
				}

				metadata := map[string]string{
					"instance_type": instanceType,
					"state":         state,
				}
				if profileArn != "" {
					metadata["instance_profile"] = profileArn
				}
				if name != "" {
					metadata["name"] = name
				}

				choices = append(choices, modules.DiscoveryChoice{
					Value:    instanceID,
					Label:    label,
					Metadata: metadata,
				})
			}
		}
	}

	return choices, nil
}

// getEC2TagValue extracts a tag value by key from a list of EC2 tags.
func getEC2TagValue(tags []types.Tag, key string) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == key {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}
