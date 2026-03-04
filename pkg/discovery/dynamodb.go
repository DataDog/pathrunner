package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"pathrunner/pkg/modules"
)

// DiscoverDynamoDBStreams lists DynamoDB tables with streams enabled
// and returns their stream ARNs as discovery choices.
func DiscoverDynamoDBStreams(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := dynamodb.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// List all tables
	var tableNames []string
	var lastTable *string
	for {
		input := &dynamodb.ListTablesInput{}
		if lastTable != nil {
			input.ExclusiveStartTableName = lastTable
		}

		result, err := client.ListTables(listCtx, input)
		if err != nil {
			if IsAccessDenied(err) {
				return nil, fmt.Errorf("%s", FormatPermissionError("EVENT_SOURCE_ARN", "dynamodb:ListTables", err))
			}
			return nil, fmt.Errorf("failed to list tables: %v", err)
		}

		tableNames = append(tableNames, result.TableNames...)

		if result.LastEvaluatedTableName == nil {
			break
		}
		lastTable = result.LastEvaluatedTableName
	}

	// Describe each table to find streams
	var choices []modules.DiscoveryChoice
	for _, tableName := range tableNames {
		descCtx, descCancel := context.WithTimeout(ctx, 10*time.Second)
		result, err := client.DescribeTable(descCtx, &dynamodb.DescribeTableInput{
			TableName: aws.String(tableName),
		})
		descCancel()

		if err != nil {
			// Skip tables we can't describe (might be access denied per-table)
			continue
		}

		table := result.Table
		if table.StreamSpecification != nil && aws.ToBool(table.StreamSpecification.StreamEnabled) && table.LatestStreamArn != nil {
			streamArn := aws.ToString(table.LatestStreamArn)
			label := fmt.Sprintf("%s (stream: %s)", tableName, string(table.StreamSpecification.StreamViewType))

			choices = append(choices, modules.DiscoveryChoice{
				Value: streamArn,
				Label: label,
				Metadata: map[string]string{
					"table_name":      tableName,
					"stream_view_type": string(table.StreamSpecification.StreamViewType),
				},
			})
		}
	}

	return choices, nil
}

// DiscoverDynamoDBTableNames lists DynamoDB tables with streams enabled
// and returns their table names as discovery choices.
func DiscoverDynamoDBTableNames(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	// Reuse the stream discovery and convert to table name choices
	streamChoices, err := DiscoverDynamoDBStreams(ctx, config)
	if err != nil {
		return nil, err
	}

	var choices []modules.DiscoveryChoice
	for _, sc := range streamChoices {
		tableName := sc.Metadata["table_name"]
		choices = append(choices, modules.DiscoveryChoice{
			Value: tableName,
			Label: sc.Label,
			Metadata: map[string]string{
				"table_name": tableName,
				"stream_arn": sc.Value,
			},
		})
	}

	return choices, nil
}
