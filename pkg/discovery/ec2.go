package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"pathrunner/pkg/modules"
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

// getEC2TagValue extracts a tag value by key from a list of EC2 tags.
func getEC2TagValue(tags []types.Tag, key string) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == key {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}
