package models

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/silinternational/serverless-mfa-api-go/domain"
	"github.com/silinternational/serverless-mfa-api-go/stores"
	"github.com/silinternational/serverless-mfa-api-go/u2fsimulator"
)

const LocalAppID = "http://localhost"

// Encode web safe base64
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
//
//	via a sha256 hashing algorithm.
//
// It returns the base64 encoded version of the marshaled version of the corresponding dsa signature {r:bigInt, s:bigInt}
// It does not use any kind of randomized data in this process
func GenerateAuthenticationSig(authData, clientData []byte, privateKey *ecdsa.PrivateKey) string {
	clientDataHash := sha256.Sum256(clientData)
	signatureData := append(authData, clientDataHash[:]...)

	publicKey := privateKey.PublicKey

	h := sha256.New()
	h.Write(signatureData)

	signHash := h.Sum(nil)
	notRandomReader := strings.NewReader(u2fsimulator.BigStrNotRandom1)

	dsaSig, asnSig := u2fsimulator.GetASN1Signature(notRandomReader, privateKey, signHash)

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

func GetTestWebauthnUsers(store *stores.Store, client *webauthn.WebAuthn) ([]User, error) {
	cred10 := webauthn.Credential{ID: []byte("C10")}
	cred20 := webauthn.Credential{ID: []byte("C20")}
	cred21 := webauthn.Credential{ID: []byte("C21")}

	// Make new, unique webauthn users with their own api keys
	apiKey0 := ApiKey{
		Key:         "1034567890123456",
		Secret:      "E086600E-3DBF-4C23-A0DA-9C55D448",
		Store:       store,
		ActivatedAt: 1,
	}

	apiKey1 := apiKey0
	apiKey1.Key = "1134567890123456"
	apiKey1.Secret = "E186600E-3DBF-4C23-A0DA-9C55D448"

	apiKey2 := apiKey0
	apiKey2.Key = "1234567890123456"
	apiKey2.Secret = "E286600E-3DBF-4C23-A0DA-9C55D448"

	testUser0 := User{
		ID:             apiKey0.Secret,
		Name:           "Nancy_NoCredential",
		DisplayName:    "Nancy NoCredential",
		Store:          store,
		WebAuthnClient: client,
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

	users := []User{testUser0, testUser1, testUser2}
	for _, u := range users {
		if err := u.EncryptAndStoreCredentials(); err != nil {
			return nil, err
		}
	}

	results, err := store.ScanTable(domain.Env.WebauthnTable)
	if err != nil {
		return nil, err
	}

	if *results.Count != 3 {
		return nil, fmt.Errorf("initial data wasn't saved properly")
	}

	return users, nil
}

func FormatDynamoResults(results any) string {
	resultsStr := fmt.Sprintf("%+v", results)
	resultsStr = strings.Replace(resultsStr, "  ", "", -1)
	resultsStr = strings.Replace(resultsStr, "\n", "", -1)

	return resultsStr
}
