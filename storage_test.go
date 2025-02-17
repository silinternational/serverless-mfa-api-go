package mfa

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
)

const TestTableName = "WebAuthn"

func (ms *MfaSuite) TestStorage_StoreLoad() {
	type fields struct {
		Table               string
		AwsEndpoint         string
		AwsRegion           string
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
			cfg, err := config.LoadDefaultConfig(
				context.Background(),
				config.WithRegion(tt.fields.AwsRegion),
				config.WithBaseEndpoint(tt.fields.AwsEndpoint),
			)
			ms.NoError(err)

			s, err := NewStorage(cfg)
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
