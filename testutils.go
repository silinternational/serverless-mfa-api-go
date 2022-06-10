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
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncbor"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
)

//

const (
	localAppID = "http://localhost"

	// 65 = AT(64) + UP(1)
	// 193 = ED(128) + AT(64) + UP(1)
	AttObjFlagUserPresent_UP      = 1
	AttObjFlagUserVerified_UV     = 2
	AttObjFlagAttestedCredData_AT = 64
	AttObjFlagExtensionData_ED    = 128
)

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

// GetAuthDataAndPrivateKey return the authentication data as a string and as a byte slice
//   and also returns the private key
func GetAuthDataAndPrivateKey(rpID, keyHandle string) (authDataStr string, authData []byte, privateKey *ecdsa.PrivateKey) {
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

// GetPublicKeyAsBytes starts with byte(4) and appends the private key's public key's X and then Y bytes
func GetPublicKeyAsBytes(privateKey *ecdsa.PrivateKey) []byte {
	pubKey := privateKey.PublicKey

	buf := []byte{0x04} // Has to start with this, apparently
	buf = append(buf, pubKey.X.Bytes()...)
	buf = append(buf, pubKey.Y.Bytes()...)

	return buf
}

// GetAttestationObject builds an attestation object for a webauth registration.
func GetAttestationObject(authDataBytes, clientData []byte, keyHandle string, privateKey *ecdsa.PrivateKey) string {
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
