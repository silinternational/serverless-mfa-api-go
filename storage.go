package mfa

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const StorageContextKey = "storage"

var (
	tableNameMissingError = errors.New("table must not be empty")
	attrNameMissingError  = errors.New("attrName must not be empty")
)

// Storage provides wrapper methods for interacting with DynamoDB
type Storage struct {
	client *dynamodb.Client
}

// NewStorage creates a new Storage service, which includes a new DynamoDB Client
func NewStorage(config aws.Config) (*Storage, error) {
	s := Storage{}
	s.client = dynamodb.NewFromConfig(config, func(o *dynamodb.Options) {
		o.EndpointOptions.DisableHTTPS = config.BaseEndpoint != nil
	})
	if s.client == nil {
		return nil, fmt.Errorf("failed to create new dynamo client")
	}

	return &s, nil
}

// Store puts item at key.
func (s *Storage) Store(table string, item interface{}) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(table),
	}

	ctx := context.Background()
	_, err = s.client.PutItem(ctx, input)
	return err
}

// Load retrieves the value at key and unmarshals it into item.
func (s *Storage) Load(table, attrName, attrVal string, item interface{}) error {
	if table == "" {
		return tableNameMissingError
	}
	if attrName == "" {
		return attrNameMissingError
	}
	if attrVal == "" {
		return errors.New("attrVal must not be empty")
	}

	input := &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{
			attrName: &types.AttributeValueMemberS{Value: attrVal},
		},
		TableName:      aws.String(table),
		ConsistentRead: aws.Bool(false),
	}

	ctx := context.Background()
	result, err := s.client.GetItem(ctx, input)
	if err != nil {
		return err
	}

	if result.Item == nil {
		return errors.New("item does not exist: " + attrVal)
	}

	return attributevalue.UnmarshalMap(result.Item, item)
}

// Delete deletes key.
func (s *Storage) Delete(table, attrName, attrVal string) error {
	if table == "" {
		return tableNameMissingError
	}
	if attrName == "" {
		return attrNameMissingError
	}

	input := &dynamodb.DeleteItemInput{
		Key: map[string]types.AttributeValue{
			attrName: &types.AttributeValueMemberS{Value: attrVal},
		},
		TableName: aws.String(table),
	}

	ctx := context.Background()
	_, err := s.client.DeleteItem(ctx, input)
	return err
}

// QueryApiKey a table using apiKey-index
func (s *Storage) QueryApiKey(table, apiKey string, items any) error {
	if table == "" {
		return tableNameMissingError
	}

	input := &dynamodb.QueryInput{
		IndexName:              aws.String("apiKey-index"),
		KeyConditionExpression: aws.String("apiKey = :val"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":val": &types.AttributeValueMemberS{Value: apiKey},
		},
		TableName: aws.String(table),
	}

	ctx := context.Background()
	result, err := s.client.Query(ctx, input)
	if err != nil {
		return err
	}

	if result.LastEvaluatedKey != nil {
		return errors.New("too many results, pagination has not been implemented")
	}

	err = attributevalue.UnmarshalListOfMaps(result.Items, &items)
	if err != nil {
		return err
	}
	return nil
}
