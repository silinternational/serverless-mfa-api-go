package mfa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncbor"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
)

const localAppID = "http://localhost"

type PublicKeyData struct {
	// Decode the results to int by default.
	_struct bool `cbor:",keyasint" json:"public_key"`
	// The type of key created. Should be OKP, EC2, or RSA.
	KeyType int64 `cbor:"1,keyasint" json:"kty"`
	// A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
	Algorithm int64 `cbor:"3,keyasint" json:"alg"`
}

type EC2PublicKeyData struct {
	PublicKeyData
	// If the key type is EC2, the curve on which we derive the signature from.
	Curve int64 `cbor:"-1,keyasint,omitempty" json:"crv"`
	// A byte string 32 bytes in length that holds the x coordinate of the key.
	XCoord []byte `cbor:"-2,keyasint,omitempty" json:"x"`
	// A byte string 32 bytes in length that holds the y coordinate of the key.
	YCoord []byte `cbor:"-3,keyasint,omitempty" json:"y"`
}

// Encode websafe base64
func encodeBase64(buf []byte) string {
	s := base64.URLEncoding.EncodeToString(buf)
	return strings.TrimRight(s, "=")
}

// Using this instead of rand.Reader, in order to have consistent
//  the private and public keys, which allows for comparison when tests fail
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

func GenerateAuthenticationSig(authData, clientData []byte, privateKey *ecdsa.PrivateKey) string {

	clientDataHash := sha256.Sum256(clientData)
	signatureData := append(authData, clientDataHash[:]...)

	publicKey := privateKey.PublicKey

	var h hash.Hash
	h = sha256.New()
	r := big.NewInt(0)
	s := big.NewInt(0)

	h.Write(signatureData)

	signhash := h.Sum(nil)

	notRandomReader := strings.NewReader(bigStrNotRandom1)
	r, s, serr := ecdsa.Sign(notRandomReader, privateKey, signhash)
	if serr != nil {
		panic("error signing: " + serr.Error())
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	dsaSig := dsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("Error encoding signature: " + err.Error())
	}

	sigStr := encodeBase64(asnSig)

	isVerified := ecdsa.Verify(&publicKey, signhash, r, s)
	if !isVerified {
		panic("start signature is not getting verified for some reason")
	}

	return sigStr
}

func GetPrivateKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	notRandomReader := strings.NewReader(bigStrNotRandom1)
	privateKey, err := ecdsa.GenerateKey(curve, notRandomReader)
	if err != nil {
		panic("error generating privateKey: " + err.Error())
	}

	return privateKey
}

// GetAuthDataAndPrivateKey return the bare authentication data as a string and as a byte slice
//   and also returns the private key
func GetAuthDataAndPrivateKey(rpID, keyHandle string) (authDataStr string, authData []byte, privateKey *ecdsa.PrivateKey) {
	// Add in the RP ID Hash (32 bytes)
	RPIDHash := sha256.Sum256([]byte(rpID))
	for _, r := range RPIDHash {
		authData = append(authData, r)
	}

	// 65 = AT(64) + UP(1)
	// 193 = ED(128) + AT(64) + UP(1)
	// add a flag
	authData = append(authData, byte(65)) // AT & UP flags

	// Add 4 bytes for counter = 0 (for now, just make it 0)
	authData = append(authData, []byte{byte(0), byte(0), byte(0), byte(0)}...)

	// Add 16 bytes for (zero) AAGUID
	aaguid := make([]byte, 16)
	authData = append(authData, aaguid...)

	credID := []byte(keyHandle)

	kHLen := len(keyHandle) // Must be less than 256
	idLen := []byte{byte(0), byte(kHLen)}

	authData = append(authData, idLen...)
	authData = append(authData, credID...)

	privateKey = GetPrivateKey()
	publicKey := privateKey.PublicKey

	pubKeyData := EC2PublicKeyData{
		PublicKeyData: PublicKeyData{
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

func GetPublicKeyAsBytes(privateKey *ecdsa.PrivateKey) []byte {
	pubKey := privateKey.PublicKey

	buf := []byte{0x04} // Has to start with this, apparently
	buf = append(buf, pubKey.X.Bytes()...)
	buf = append(buf, pubKey.Y.Bytes()...)

	return buf
}

func GetAttestationObject(authDataBytes, clientData []byte, keyHandle string, privateKey *ecdsa.PrivateKey) string {
	bigNumStr := "123456789012345678901234567890123456789012345678901234567890123456789012345678"
	bigNum := new(big.Int)
	bigNum, ok := bigNum.SetString(bigNumStr, 10)
	if !ok {
		panic("failed to set bigNumber to string")
	}
	attestationCertBytes := GetCertBytes(privateKey, bigNum, bigStrNotRandom1)

	notRandomReader := strings.NewReader(bigStrNotRandom1)
	signature := GetSignature(notRandomReader, clientData, keyHandle, privateKey)

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

func GetSignature(notRandom io.Reader, clientData []byte, keyHandle string, privateKey *ecdsa.PrivateKey) []byte {

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

	r, s, err := ecdsa.Sign(notRandom, privateKey, digest[:])
	if err != nil {
		panic("error generating signature: " + err.Error())
	}

	dsaSig := dsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("error encoding signature: " + err.Error())
	}

	return asnSig
}
