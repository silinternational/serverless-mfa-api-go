package mfa

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
)

var (
	storage   *Storage
	envConfig EnvConfig
)

// EnvConfig holds environment specific configurations and is populated on init
type EnvConfig struct {
	ApiKeyTable   string `required:"true" split_words:"true"`
	WebauthnTable string `required:"true" split_words:"true"`

	AwsEndpoint      string `default:"" split_words:"true"`
	AwsDefaultRegion string `default:"" split_words:"true"`
	AwsDisableSSL    bool   `default:"false" split_words:"true"`

	AWSConfig *aws.Config `json:"-"`
}

func (e *EnvConfig) InitAWS() {
	e.AWSConfig = &aws.Config{
		DisableSSL: aws.Bool(e.AwsDisableSSL),
	}

	if e.AwsEndpoint != "" {
		e.AWSConfig.Endpoint = aws.String(e.AwsEndpoint)
	}

	if e.AwsDefaultRegion != "" {
		e.AWSConfig.Region = aws.String(e.AwsDefaultRegion)
	}
}

func (e *EnvConfig) String() string {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("error stringifying envConfig: %s", err)
	}
	return string(b)
}

func SetConfig(c EnvConfig) {
	envConfig = c
	log.Println("config:", envConfig.String())
}
