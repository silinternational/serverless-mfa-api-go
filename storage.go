package mfa

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

// Storage provides wrapper methods for interacting with DynamoDB
type Storage struct {
	awsSession *session.Session
	client     *dynamodb.DynamoDB
}

func NewStorage(config *aws.Config) (*Storage, error) {
	s := Storage{}

	var err error
	s.awsSession, err = session.NewSession(config)
	if err != nil {
		return &Storage{}, err
	}

	s.client = dynamodb.New(s.awsSession)
	if s.client == nil {
		return nil, fmt.Errorf("faild to create new dynamo client")
	}

	return &s, nil
}

// Store puts item at key.
func (s *Storage) Store(table string, item interface{}) error {
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(table),
	}

	_, err = s.client.PutItem(input)
	return err
}

// Load retrieves the value at key and unmarshal it into item.
func (s *Storage) Load(table, attrName, attrVal string, item interface{}) error {
	if table == "" {
		return errors.New("table must not be empty")
	}
	if attrName == "" {
		return errors.New("attrName must not be empty")
	}
	if attrVal == "" {
		return errors.New("attrVal must not be empty")
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

	result, err := s.client.GetItem(input)
	if err != nil {
		return err
	}

	err = dynamodbattribute.UnmarshalMap(result.Item, item)
	return err
}

// Delete deletes key.
func (s *Storage) Delete(table, attrName, attrVal string) error {
	if table == "" {
		return errors.New("table must not be empty")
	}
	if attrName == "" {
		return errors.New("attrName must not be empty")
	}

	input := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			attrName: {
				S: aws.String(attrVal),
			},
		},
		TableName: aws.String(table),
	}

	_, err := s.client.DeleteItem(input)
	return err
}
