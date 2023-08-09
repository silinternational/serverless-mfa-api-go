package mfa

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/go-webauthn/webauthn/webauthn"
)

type baseTestConfig struct {
	AwsConfig      aws.Config
	EnvConfig      EnvConfig
	Storage        *Storage
	WebAuthnClient *webauthn.WebAuthn
}

func getDBConfig(ms *MfaSuite) baseTestConfig {
	awsConfig := testAwsConfig()
	envCfg := testEnvConfig(awsConfig)
	localStorage, err := NewStorage(&awsConfig)
	ms.NoError(err, "failed creating local storage for test")

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",   // Display Name for your site
		RPID:          "111.11.11.11", // Generally the FQDN for your site
		Debug:         true,
	})

	ms.NoError(err, "failed creating new webAuthnClient for test")

	return baseTestConfig{
		AwsConfig:      awsConfig,
		EnvConfig:      envCfg,
		Storage:        localStorage,
		WebAuthnClient: web,
	}
}

func getTestWebauthnUsers(ms *MfaSuite, config baseTestConfig) []DynamoUser {
	cred10 := webauthn.Credential{ID: []byte("C10")}
	cred20 := webauthn.Credential{ID: []byte("C20")}
	cred21 := webauthn.Credential{ID: []byte("C21")}

	// Make new, unique webauthn users with their own api keys
	apiKey0 := ApiKey{
		Key:         "1034567890123456",
		Secret:      "E086600E-3DBF-4C23-A0DA-9C55D448",
		Store:       config.Storage,
		ActivatedAt: 1,
	}

	apiKey1 := apiKey0
	apiKey1.Key = "1134567890123456"
	apiKey1.Secret = "E186600E-3DBF-4C23-A0DA-9C55D448"

	apiKey2 := apiKey0
	apiKey2.Key = "1234567890123456"
	apiKey2.Secret = "E286600E-3DBF-4C23-A0DA-9C55D448"

	testUser0 := DynamoUser{
		ID:             apiKey0.Secret,
		Name:           "Nancy_NoCredential",
		DisplayName:    "Nancy NoCredential",
		Store:          config.Storage,
		WebAuthnClient: config.WebAuthnClient,
		ApiKey:         apiKey0,
		ApiKeyValue:    apiKey0.Key,
		Credentials:    []webauthn.Credential{},
	}

	testUser1 := testUser0
	testUser1.ID = apiKey1.Secret
	testUser1.Name = "Oscar_OneCredential"
	testUser1.DisplayName = "Oscar OneCredential"
	testUser1.ApiKey = apiKey1
	testUser1.ApiKeyValue = apiKey1.Key
	testUser1.Credentials = []webauthn.Credential{cred10}

	testUser2 := testUser0
	testUser2.ID = apiKey2.Secret
	testUser2.Name = "Tony_TwoCredentials"
	testUser2.DisplayName = "Tony TwoCredentials"
	testUser2.ApiKey = apiKey2
	testUser2.ApiKeyValue = apiKey2.Key
	testUser2.Credentials = []webauthn.Credential{cred20, cred21}

	// add dummy legacy u2f data to first user
	testUser0.AppId = "someAppId"
	testUser0.EncryptedAppId = "someEncryptedAppId"
	testUser0.KeyHandle = "someKeyHandle"
	testUser0.EncryptedKeyHandle = "someEncryptedKeyHandle"
	testUser0.PublicKey = "somePublicKey"
	testUser0.EncryptedPublicKey = "someEncryptedPublicKey"

	for _, u := range []DynamoUser{testUser0, testUser1, testUser2} {
		ms.NoError(u.encryptAndStoreCredentials(), "failed saving initial test user")
	}

	params := &dynamodb.ScanInput{
		TableName: aws.String(config.EnvConfig.WebauthnTable),
	}

	results, err := config.Storage.client.Scan(params)
	ms.NoError(err, "failed to scan storage for new user entries")

	resultsStr := formatDynamoResults(results)
	ms.Contains(resultsStr, "Count: 3", "initial data wasn't saved properly")

	return []DynamoUser{testUser0, testUser1, testUser2}
}
