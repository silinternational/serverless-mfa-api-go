package mfa

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	u2fsim "github.com/silinternational/serverless-mfa-api-go/u2fsimulator"
)

const localAppID = "http://localhost"

func testAwsConfig() aws.Config {
	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion(os.Getenv("AWS_DEFAULT_REGION")),
		config.WithBaseEndpoint(os.Getenv("AWS_ENDPOINT")),
	)
	if err != nil {
		panic("testAwsConfig failed at LoadDefaultConfig: " + err.Error())
	}
	return cfg
}

func testEnvConfig(awsConfig aws.Config) EnvConfig {
	envCfg := EnvConfig{
		ApiKeyTable:      "ApiKey",
		WebauthnTable:    "WebAuthn",
		AwsEndpoint:      os.Getenv("AWS_ENDPOINT"),
		AwsDefaultRegion: os.Getenv("AWS_DEFAULT_REGION"),
		AWSConfig:        awsConfig,
	}

	SetConfig(envCfg)
	return envCfg
}

func initDb(storage *Storage) error {
	var err error
	if storage == nil {
		storage, err = NewStorage(testAwsConfig())
		if err != nil {
			return err
		}
	}

	ctx := context.Background()

	// attempt to delete tables in case already exists
	tables := map[string]string{"WebAuthn": "uuid", "ApiKey": "value"}
	for name := range tables {
		deleteTable := &dynamodb.DeleteTableInput{
			TableName: aws.String(name),
		}
		_, _ = storage.client.DeleteTable(ctx, deleteTable)
	}

	// create tables
	for table, attr := range tables {
		createTable := &dynamodb.CreateTableInput{
			AttributeDefinitions: []types.AttributeDefinition{
				{
					AttributeName: aws.String(attr),
					AttributeType: types.ScalarAttributeTypeS,
				},
			},
			KeySchema: []types.KeySchemaElement{
				{
					AttributeName: aws.String(attr),
					KeyType:       types.KeyTypeHash,
				},
			},
			ProvisionedThroughput: &types.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(3),
				WriteCapacityUnits: aws.Int64(3),
			},
			TableName: aws.String(table),
		}
		_, err = storage.client.CreateTable(ctx, createTable)
		if err != nil {
			return err
		}
	}

	return nil
}

// Encode websafe base64
func encodeBase64(buf []byte) string {
	s := base64.URLEncoding.EncodeToString(buf)
	return strings.TrimRight(s, "=")
}

// SignResponse as defined by the FIDO U2F Javascript API.
type SignResponse struct {
	KeyHandle     string `json:"keyHandle"`
	SignatureData string `json:"signatureData"`
	ClientData    string `json:"clientData"`
}

// ClientData as defined by the FIDO U2F Raw Message Formats specification.
type ClientData struct {
	Typ          string          `json:"type"`
	Challenge    string          `json:"challenge"`
	Origin       string          `json:"origin"`
	CIDPublicKey json.RawMessage `json:"cid_pubkey"`
}

// GenerateAuthenticationSig appends the clientData to the authData and uses the privateKey's public Key to sign it
// via a sha256 hashing algorithm.
// It returns the base64 encoded version of the marshaled version of the corresponding dsa signature {r:bigInt, s:bigInt}
// It does not use any kind of randomized data in this process
func GenerateAuthenticationSig(authData, clientData []byte, privateKey *ecdsa.PrivateKey) string {
	clientDataHash := sha256.Sum256(clientData)
	signatureData := append(authData, clientDataHash[:]...)

	publicKey := privateKey.PublicKey

	h := sha256.New()
	h.Write(signatureData)

	signHash := h.Sum(nil)
	notRandomReader := strings.NewReader(u2fsim.BigStrNotRandom1)

	dsaSig, asnSig := u2fsim.GetASN1Signature(notRandomReader, privateKey, signHash)

	if !ecdsa.Verify(&publicKey, signHash, dsaSig.R, dsaSig.S) {
		panic("start signature is not getting verified for some reason")
	}

	return encodeBase64(asnSig)
}

// GetPublicKeyAsBytes starts with byte(4) and appends the private key's public key's X and then Y bytes
func GetPublicKeyAsBytes(privateKey *ecdsa.PrivateKey) []byte {
	pubKey := privateKey.PublicKey

	buf := []byte{0x04} // Has to start with this, apparently
	buf = append(buf, pubKey.X.Bytes()...)
	buf = append(buf, pubKey.Y.Bytes()...)

	return buf
}
