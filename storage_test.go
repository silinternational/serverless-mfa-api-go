package mfa

import (
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

const TestTableName = "WebAuthn"
const DisableSSL = true

func initDb(storage *Storage) error {
	var err error
	if storage == nil {
		storage, err = NewStorage(&aws.Config{
			Endpoint:   aws.String(os.Getenv("AWS_ENDPOINT")),
			Region:     aws.String(os.Getenv("AWS_DEFAULT_REGION")),
			DisableSSL: aws.Bool(true),
		})
		if err != nil {
			return err
		}
	}

	// attempt to delete tables in case already exists
	tables := map[string]string{"WebAuthn": "uuid", "ApiKey": "value"}
	for name, _ := range tables {
		deleteTable := &dynamodb.DeleteTableInput{
			TableName: aws.String(name),
		}
		_, err = storage.client.DeleteTable(deleteTable)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case dynamodb.ErrCodeResourceNotFoundException:
					// this is fine
				default:
					return aerr
				}
			} else {
				return err
			}
		}
	}

	// create tables
	for table, attr := range tables {
		createTable := &dynamodb.CreateTableInput{
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				{
					AttributeName: aws.String(attr),
					AttributeType: aws.String("S"),
				},
			},
			KeySchema: []*dynamodb.KeySchemaElement{
				{
					AttributeName: aws.String(attr),
					KeyType:       aws.String("HASH"),
				},
			},
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(3),
				WriteCapacityUnits: aws.Int64(3),
			},
			TableName: aws.String(table),
		}
		_, err = storage.client.CreateTable(createTable)
		if err != nil {
			return err
		}
	}

	return nil
}

func TestStorage_StoreLoad(t *testing.T) {
	err := initDb(nil)
	if err != nil {
		t.Error(err)
		return
	}

	type fields struct {
		Table               string
		AwsSession          *session.Session
		AwsEndpoint         string
		AwsRegion           string
		AwsDisableSSL       bool
		PrimaryKeyAttribute string
	}
	type args struct {
		key  string
		item interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "simple test",
			fields: fields{
				Table:               TestTableName,
				AwsEndpoint:         os.Getenv("AWS_ENDPOINT"),
				AwsRegion:           os.Getenv("AWS_DEFAULT_REGION"),
				AwsDisableSSL:       DisableSSL,
				PrimaryKeyAttribute: "uuid",
			},
			args: args{
				key: "2B28BED1-1225-4EC9-98F9-EAB8FBCEDBA0",
				item: &DynamoUser{
					ID:          "2B28BED1-1225-4EC9-98F9-EAB8FBCEDBA0",
					Name:        "test_user",
					DisplayName: "Test User",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewStorage(&aws.Config{
				Endpoint:   aws.String(tt.fields.AwsEndpoint),
				Region:     aws.String(tt.fields.AwsRegion),
				DisableSSL: aws.Bool(tt.fields.AwsDisableSSL),
			})
			if err != nil {
				t.Error(err)
				return
			}
			err = s.Store(tt.fields.Table, tt.args.item)
			if (err != nil) != tt.wantErr {
				t.Errorf("Store() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				var user DynamoUser
				err := s.Load(tt.fields.Table, "uuid", tt.args.key, &user)
				if err != nil {
					t.Errorf("unable to load, error: %s", err.Error())
					return
				}

				if user.ID != tt.args.key {
					t.Errorf("resulting id not expected, got: %s, expected: %s", user.ID, tt.args.key)
					return
				}
			}
		})
	}
}
