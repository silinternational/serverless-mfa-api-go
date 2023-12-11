package stores

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

// Storage provides wrapper methods for interacting with Store
type Store struct {
	awsSession *session.Session
	client     *dynamodb.DynamoDB
}

func NewStore(config *aws.Config) (*Store, error) {
	s := Store{}

	var err error
	s.awsSession, err = session.NewSession(config)
	if err != nil {
		return nil, err
	}

	s.client = dynamodb.New(s.awsSession)
	if s.client == nil {
		return nil, fmt.Errorf("failed to create new dynamo client")
	}

	return &s, nil
}

// Store puts item at key. Fails if already exists
func (d *Store) Create(table string, item any) error {
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:                av,
		TableName:           aws.String(table),
		ConditionExpression: aws.String("attribute_not_exists(Id)"),
	}

	_, err = d.client.PutItem(input)
	return err
}

// Store puts item at key.
func (d *Store) Save(table string, item any) error {
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(table),
	}

	_, err = d.client.PutItem(input)
	return err
}

// Load retrieves the value at key and unmarshals it into item.
func (d *Store) Load(table, attrName, attrVal string, item any) error {
	result, err := d.getItem(table, attrName, attrVal)
	if err != nil {
		return err
	}

	return dynamodbattribute.UnmarshalMap(result.Item, item)
}

// Delete deletes key.
func (d *Store) Delete(table, attrName, attrVal string) error {
	if err := assertRequired(table, attrName, attrVal); err != nil {
		return err
	}

	input := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			attrName: {
				S: aws.String(attrVal),
			},
		},
		TableName: aws.String(table),
	}

	_, err := d.client.DeleteItem(input)
	return err
}

// HasItem returns if the item exists
func (d *Store) HasItem(table, attrName, attrVal string) (bool, error) {
	_, err := d.getItem(table, attrName, attrVal)
	if aErr, ok := err.(awserr.Error); err != nil && ok && aErr.Code() == dynamodb.ErrCodeResourceNotFoundException {
		return false, nil
	}
	return err == nil, err
}

func (d *Store) CreateTable(table, key string) error {
	createTable := &dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String(key),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String(key),
				KeyType:       aws.String("HASH"),
			},
		},
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(3),
			WriteCapacityUnits: aws.Int64(3),
		},
		TableName: aws.String(table),
	}

	_, err := d.client.CreateTable(createTable)
	return err
}

func (d *Store) DeleteTable(name string) error {
	deleteTable := &dynamodb.DeleteTableInput{
		TableName: aws.String(name),
	}

	_, err := d.client.DeleteTable(deleteTable)
	if aErr, _ := err.(awserr.Error); err != nil && aErr.Code() != dynamodb.ErrCodeResourceNotFoundException {
		return err
	}
	return nil
}

func (d *Store) ScanTable(name string) (*dynamodb.ScanOutput, error) {
	params := &dynamodb.ScanInput{
		TableName: aws.String(name),
	}

	return d.client.Scan(params)
}

func (d *Store) getItem(table, attrName, attrVal string) (*dynamodb.GetItemOutput, error) {
	if err := assertRequired(table, attrName, attrVal); err != nil {
		return nil, err
	}

	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			attrName: {
				S: aws.String(attrVal),
			},
		},
		TableName:      aws.String(table),
		ConsistentRead: aws.Bool(false),
	}

	return d.client.GetItem(input)
}

func assertRequired(table, attrName, attrVal string) error {
	if table == "" {
		return errors.New("table must not be empty")
	}
	if attrName == "" {
		return errors.New("attrName must not be empty")
	}
	if attrVal == "" {
		return errors.New("attrVal must not be empty")
	}

	return nil
}
