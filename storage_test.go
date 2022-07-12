package mfa

import (
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

const TestTableName = "WebAuthn"
const DisableSSL = true

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
