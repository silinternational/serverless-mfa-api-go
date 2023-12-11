package stores

import (
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

const (
	TestTableName = "WebAuthn"
)

func initDb() (*Store, error) {
	storage, err := NewStore(&aws.Config{
		Endpoint:   aws.String(os.Getenv("AWS_ENDPOINT")),
		Region:     aws.String(os.Getenv("AWS_DEFAULT_REGION")),
		DisableSSL: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}

	// attempt to delete tables in case already exists
	tables := map[string]string{"WebAuthn": "uuid", "ApiKey": "value"}
	for name := range tables {
		err := storage.DeleteTable(name)
		if err != nil {
			if aErr, ok := err.(awserr.Error); ok {
				switch aErr.Code() {
				case dynamodb.ErrCodeResourceNotFoundException:
					continue // this is fine
				default:
					return nil, aErr
				}
			} else {
				return nil, err
			}
		}
	}

	// create tables
	for table, attr := range tables {
		if err := storage.CreateTable(table, attr); err != nil {
			return nil, err
		}
	}

	return storage, nil
}

func TestStorage_StoreLoad(t *testing.T) {
	s, err := initDb()
	if err != nil {
		t.Error(err)
		return
	}

	type fields struct {
		Table               string
		PrimaryKeyAttribute string
	}
	type args struct {
		key  string
		item any
	}
	type user struct {
		ID          string
		Name        string
		DisplayName string
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
				PrimaryKeyAttribute: "uuid",
			},
			args: args{
				key: "2B28BED1-1225-4EC9-98F9-EAB8FBCEDBA0",
				item: &user{
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
			err = s.Save(tt.fields.Table, tt.args.item)
			if (err != nil) != tt.wantErr {
				t.Errorf("Store() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				var user user
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
