package mfa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

const (
	localAppID = "http://localhost"

	// The authenticatorData value includes bytes that refer to these flags.
	// Multiple flags can be combined through addition. For example,
	// including the UserPresent (UP) and AttestedCredentialData (AT) flags would be done
	// by using the value 65.
	// AT(64) + UP(1) = 65
	AttObjFlagUserPresent_UP      = 1
	AttObjFlagUserVerified_UV     = 2
	AttObjFlagAttestedCredData_AT = 64
	AttObjFlagExtensionData_ED    = 128
)

func testAwsConfig() aws.Config {
	return aws.Config{
		Endpoint:   aws.String(os.Getenv("AWS_ENDPOINT")),
		Region:     aws.String(os.Getenv("AWS_DEFAULT_REGION")),
		DisableSSL: aws.Bool(true),
	}
}

func testEnvConfig(awsConfig aws.Config) EnvConfig {
	envCfg := EnvConfig{
		ApiKeyTable:      "ApiKey",
		WebauthnTable:    "WebAuthn",
		AwsEndpoint:      os.Getenv("AWS_ENDPOINT"),
		AwsDefaultRegion: os.Getenv("AWS_DEFAULT_REGION"),
		AwsDisableSSL:    true,
		AWSConfig:        &awsConfig,
	}

	SetConfig(envCfg)
	return envCfg
}

func initDb(storage *Storage) error {
	var err error
	if storage == nil {
		awsCfg := testAwsConfig()
		storage, err = NewStorage(&aws.Config{
			Endpoint:   awsCfg.Endpoint,
			Region:     awsCfg.Region,
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

// Encode websafe base64
func encodeBase64(buf []byte) string {
	s := base64.URLEncoding.EncodeToString(buf)
	return strings.TrimRight(s, "=")
}

// Using this instead of rand.Reader, in order to have consistent
//  private and public keys, which allows for comparison when tests fail
const bigStrNotRandom1 = "11111111111111111111111111111111111111111"

// SignResponse as defined by the FIDO U2F Javascript API.
type SignResponse struct {
	KeyHandle     string `json:"keyHandle"`
	SignatureData string `json:"signatureData"`
	ClientData    string `json:"clientData"`
}

// Internal type for ASN1 coercion
type dsaSignature struct {
	R, S *big.Int
}

// ClientData as defined by the FIDO U2F Raw Message Formats specification.
type ClientData struct {
	Typ          string          `json:"type"`
	Challenge    string          `json:"challenge"`
	Origin       string          `json:"origin"`
	CIDPublicKey json.RawMessage `json:"cid_pubkey"`
}

// GenerateAuthenticationSig appends the clientData to the authData and uses the privateKey's public Key to sign it
//  via a sha256 hashing algorithm.
// It returns the base64 encoded version of the marshaled version of the corresponding dsa signature {r:bigInt, s:bigInt}
// It does not use any kind of randomized data in this process
func GenerateAuthenticationSig(authData, clientData []byte, privateKey *ecdsa.PrivateKey) string {

	clientDataHash := sha256.Sum256(clientData)
	signatureData := append(authData, clientDataHash[:]...)

	publicKey := privateKey.PublicKey

	h := sha256.New()
	h.Write(signatureData)

	signHash := h.Sum(nil)
	notRandomReader := strings.NewReader(bigStrNotRandom1)

	dsaSig, asnSig := getASN1Signature(notRandomReader, privateKey, signHash)

	if !ecdsa.Verify(&publicKey, signHash, dsaSig.R, dsaSig.S) {
		panic("start signature is not getting verified for some reason")
	}

	return encodeBase64(asnSig)
}

// GetPrivateKey returns a newly generated ecdsa private key without using any kind of randomizing
func GetPrivateKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	notRandomReader := strings.NewReader(bigStrNotRandom1)
	privateKey, err := ecdsa.GenerateKey(curve, notRandomReader)
	if err != nil {
		panic("error generating privateKey: " + err.Error())
	}

	return privateKey
}

// GetPublicKeyAsBytes starts with byte(4) and appends the private key's public key's X and then Y bytes
func GetPublicKeyAsBytes(privateKey *ecdsa.PrivateKey) []byte {
	pubKey := privateKey.PublicKey

	buf := []byte{0x04} // Has to start with this, apparently
	buf = append(buf, pubKey.X.Bytes()...)
	buf = append(buf, pubKey.Y.Bytes()...)

	return buf
}

// GetCertBytes generates an x509 certificate without using any kind of randomization
// Most of this was borrowed from https://github.com/ryankurte/go-u2f
func GetCertBytes(privateKey *ecdsa.PrivateKey, serialNumber *big.Int, certReaderStr string) []byte {
	template := x509.Certificate{}

	template.SerialNumber = serialNumber
	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign

	template.NotBefore = time.Date(2022, 1, 1, 1, 1, 1, 1, time.UTC)
	template.NotAfter = time.Date(2122, 1, 1, 1, 1, 1, 1, time.UTC) // 100 years

	template.SignatureAlgorithm = x509.ECDSAWithSHA256

	newReader := strings.NewReader(certReaderStr)

	certBytes, err := x509.CreateCertificate(newReader, &template, &template, &(privateKey.PublicKey), privateKey)
	if err != nil {
		panic("error creating x509 certificate " + err.Error())
	}

	return certBytes
}

// GetSignatureForAttObject starts with byte(0) and appends the sha256 sum of the localAppID and of the clientData
//  and then appends the keyHandle and an elliptic Marshalled version of the public key
//  It does a sha256 sum of that and creates a dsa signature of it with the private key and without using any
//  randomizing
func GetSignatureForAttObject(notRandom io.Reader, clientData []byte, keyHandle string, privateKey *ecdsa.PrivateKey) []byte {

	appParam := sha256.Sum256([]byte(localAppID))
	challenge := sha256.Sum256(clientData)

	publicKey := privateKey.PublicKey

	buf := []byte{0}
	buf = append(buf, appParam[:]...)
	buf = append(buf, challenge[:]...)
	buf = append(buf, keyHandle...)
	pk := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
	buf = append(buf, pk...)

	digest := sha256.Sum256(buf)
	_, asnSig := getASN1Signature(notRandom, privateKey, digest[:])
	return asnSig
}

func getASN1Signature(notRandom io.Reader, privateKey *ecdsa.PrivateKey, sha256Digest []byte) (dsaSignature, []byte) {

	r, s, err := ecdsa.Sign(notRandom, privateKey, sha256Digest[:])
	if err != nil {
		panic("error generating signature: " + err.Error())
	}

	dsaSig := dsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("error encoding signature: " + err.Error())
	}

	return dsaSig, asnSig
}
