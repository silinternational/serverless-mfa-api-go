package domain

import "github.com/aws/aws-sdk-go/aws"

var Env env

type env struct {
	ApiKeyTable   string `required:"true" split_words:"true"`
	WebauthnTable string `required:"true" split_words:"true"`

	AwsEndpoint      string `default:"" split_words:"true"`
	AwsDefaultRegion string `default:"" split_words:"true"`
	AwsDisableSSL    bool   `default:"false" split_words:"true"`

	AWSConfig *aws.Config `ignored:"true"`
}

func (e *env) setAWSConfig() {
	c := &aws.Config{
		DisableSSL: aws.Bool(e.AwsDisableSSL),
	}

	if e.AwsEndpoint != "" {
		c.Endpoint = aws.String(e.AwsEndpoint)
	}

	if e.AwsDefaultRegion != "" {
		c.Region = aws.String(e.AwsDefaultRegion)
	}

	e.AWSConfig = c
}
