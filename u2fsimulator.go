package mfa

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncbor"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
)

const DefaultKeyHandle = `U2fSimulatorKey`

func randomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	includeLetters := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_0123456789"
	letters := []rune(includeLetters)
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))] // #nosec G404
	}
	return string(b)
}

func getClientDataJson(ceremonyType, challenge string) (string, []byte) {
	if ceremonyType != "webauthn.create" && ceremonyType != "webauthn.get" {
		panic(`ceremonyType must be "webauthn.create" or "webauthn.get"`)

	}

	cd := ClientData{
		Typ:       ceremonyType,
		Origin:    localAppID,
		Challenge: challenge,
	}

	cdJson, _ := json.Marshal(cd)

	clientData := base64.URLEncoding.EncodeToString(cdJson)
	return clientData, cdJson
}

// getAuthDataAndPrivateKey return the authentication data as a string and as a byte slice
//   and also returns the private key
func getAuthDataAndPrivateKey(rpID, keyHandle string) (authDataStr string, authData []byte, privateKey *ecdsa.PrivateKey) {
	// Add in the RP ID Hash (32 bytes)
	RPIDHash := sha256.Sum256([]byte(rpID))
	for _, r := range RPIDHash {
		authData = append(authData, r)
	}

	authData = append(authData, byte(AttObjFlagAttestedCredData_AT+AttObjFlagUserPresent_UP)) // AT & UP flags

	// Add 4 bytes for counter = 0 (for now, just make it 0)
	authData = append(authData, []byte{byte(0), byte(0), byte(0), byte(0)}...)

	// Add 16 bytes for (zero) AAGUID
	aaguid := make([]byte, 16)
	authData = append(authData, aaguid...)

	credID := []byte(keyHandle)

	kHLen := len(keyHandle)
	if kHLen >= 256 {
		panic("the length of the keyHandle must be less than 256")
	}
	idLen := []byte{byte(0), byte(kHLen)}

	authData = append(authData, idLen...)
	authData = append(authData, credID...)

	privateKey = GetPrivateKey()
	publicKey := privateKey.PublicKey

	pubKeyData := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			Algorithm: int64(webauthncose.AlgES256),
			KeyType:   int64(webauthncose.EllipticKey),
		},
		XCoord: publicKey.X.Bytes(),
		YCoord: publicKey.Y.Bytes(),
	}

	// Get the CBOR-encoded representation of the OKPPublicKeyData
	pubKeyBytes, err := webauthncbor.Marshal(pubKeyData)
	if err != nil {
		panic("error Marshaling publicKeyData: " + err.Error())
	}

	authData = append(authData, pubKeyBytes...)
	authDataStr = base64.RawURLEncoding.EncodeToString(authData)
	return authDataStr, authData, privateKey
}

// getAttestationObject builds an attestation object for a webauth registration.
func getAttestationObject(authDataBytes, clientData []byte, keyHandle string, privateKey *ecdsa.PrivateKey) string {
	bigNumStr := "123456789012345678901234567890123456789012345678901234567890123456789012345678"
	bigNum := new(big.Int)
	bigNum, ok := bigNum.SetString(bigNumStr, 10)
	if !ok {
		panic("failed to set bigNumber to string")
	}
	attestationCertBytes := GetCertBytes(privateKey, bigNum, bigStrNotRandom1)

	notRandomReader := strings.NewReader(bigStrNotRandom1)
	signature := GetSignatureForAttObject(notRandomReader, clientData, keyHandle, privateKey)

	attObj := protocol.AttestationObject{
		Format: "fido-u2f",

		RawAuthData: authDataBytes,
		AttStatement: map[string]interface{}{
			`x5c`: []interface{}{attestationCertBytes},
			`sig`: signature,
		},
	}

	marshalledAttObj, err := webauthncbor.Marshal(&attObj)
	if err != nil {
		panic("error marshalling AttestationObject: " + err.Error())
	}

	b64RawURL := base64.RawURLEncoding.EncodeToString(marshalledAttObj)
	return b64RawURL
}

type AttObjectClientData struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}
type U2fRegistrationResponse struct {
	ID                     string              `json:"id"`
	RawID                  string              `json:"rawId"`
	Response               AttObjectClientData `json:"response"`
	ClientExtensionResults map[string]string   `json:"clientExtensionResults"`
	Type                   string              `json:"type"`
	Transports             []string            `json:"transports"`
}

// U2fRegistration is intended to assist with automated testing by
//   returning to an api server what a client
//   would return following a registration ceremony with a U2F key
// It expects a POST call with the following elements in the body/form
//	"challenge"
//	"relying_party_id"
//	"keyHandle" (optional)
// Although the api server wouldn't normally deal with a challenge and keyHandle,
//   including them here allows for more predictability with the test results
func U2fRegistration(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}
	challenge := r.Form.Get("challenge")
	rpID := r.Form.Get("relying_party_id")
	keyHandle := r.Form.Get("keyHandle")

	if keyHandle == "" {
		keyHandle = DefaultKeyHandle
	}

	clientDataStr, clientData := getClientDataJson("webauthn.create", challenge)
	_, authDataBytes, privateKey := getAuthDataAndPrivateKey(rpID, keyHandle)

	attestationObject := getAttestationObject(authDataBytes, clientData, keyHandle, privateKey)

	id := randomString(43)

	resp := U2fRegistrationResponse{
		ID:    id,
		RawID: id,
		Response: AttObjectClientData{
			AttestationObject: attestationObject,
			ClientDataJSON:    clientDataStr,
		},
		ClientExtensionResults: map[string]string{},
		Type:                   "public-key",
		Transports:             []string{"usb"},
	}

	jsonResponse(w, resp, http.StatusOK)
}
