package mfa

import (
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

const TestTableName = "WebAuthn"
const DisableSSL = true

func (ms *MfaSuite) TestStorage_StoreLoad() {
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
		ms.T().Run(tt.name, func(t *testing.T) {
			s, err := NewStorage(&aws.Config{
				Endpoint:   aws.String(tt.fields.AwsEndpoint),
				Region:     aws.String(tt.fields.AwsRegion),
				DisableSSL: aws.Bool(tt.fields.AwsDisableSSL),
			})
			ms.NoError(err)
			err = s.Store(tt.fields.Table, tt.args.item)
			if tt.wantErr {
				ms.Error(err, "didn't get an expected error Store()")
				return
			}

			ms.NoError(err, "unexpected error with Store()")
			var user DynamoUser
			ms.NoError(s.Load(tt.fields.Table, "uuid", tt.args.key, &user), "error with s.Load()")

			ms.Equal(tt.args.key, user.ID, "incorrect user.ID")
		})
	}
}
