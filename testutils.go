package mfa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"strings"

	"github.com/duo-labs/webauthn/protocol/webauthncbor"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
)

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

// Decode websafe base64
func decodeBase64(s string) ([]byte, error) {
	for i := 0; i < len(s)%4; i++ {
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// Encode websafe base64
func encodeBase64(buf []byte) string {
	s := base64.URLEncoding.EncodeToString(buf)
	return strings.TrimRight(s, "=")
}

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

func GenerateAuthenticationSig(appId string, clientData []byte) string {
	// Build signature data
	var signatureData []byte
	// User presence
	signatureData = append(signatureData, 0x01)
	// Use counter
	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, uint32(0))
	signatureData = append(signatureData, countBuf...)

	notRandomReader := strings.NewReader(bigStrNotRandom1)

	appParam := sha256.Sum256([]byte(appId))
	challenge := sha256.Sum256(clientData)

	var buf []byte
	buf = append(buf, appParam[:]...)
	buf = append(buf, signatureData...)
	buf = append(buf, challenge[:]...)

	digest := sha256.Sum256([]byte(buf))
	privateKey := GetPrivateKey()

	r, s, err := ecdsa.Sign(notRandomReader, privateKey, digest[:])
	if err != nil {
		panic("Error generating signature: " + err.Error())
	}

	dsaSig := dsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("Error encoding signature: " + err.Error())
	}

	sigStr := encodeBase64(asnSig)

	return sigStr
}

func GenerateAuthenticationSigFromPrivateKey(appId string, clientData []byte, privateKey *ecdsa.PrivateKey) string {
	// Build signature data
	var signatureData []byte
	// User presence
	signatureData = append(signatureData, 0x01)
	// Use counter
	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, uint32(0))
	signatureData = append(signatureData, countBuf...)

	notRandomReader := strings.NewReader(bigStrNotRandom1)

	appParam := sha256.Sum256([]byte(appId))
	challenge := sha256.Sum256(clientData)

	var buf []byte
	buf = append(buf, appParam[:]...)
	buf = append(buf, signatureData...)
	buf = append(buf, challenge[:]...)

	digest := sha256.Sum256([]byte(buf))

	r, s, err := ecdsa.Sign(notRandomReader, privateKey, digest[:])
	if err != nil {
		panic("Error generating signature: " + err.Error())
	}

	dsaSig := dsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("Error encoding signature: " + err.Error())
	}

	sigStr := encodeBase64(asnSig)

	return sigStr
}

func GenerateAuthenticationSigFromPrivateKey2(authData, clientData []byte, privateKey *ecdsa.PrivateKey) string {
	//clientDataHash := sha256.Sum256(p.Raw.AssertionResponse.ClientDataJSON)

	clientDataHash := sha256.Sum256(clientData)
	fmt.Printf("\nStartClientData: %v\nStartCDHash: %v\n", clientData, clientDataHash)
	signatureData := append(authData, clientDataHash[:]...)

	notRandomReader := strings.NewReader(bigStrNotRandom1)
	r, s, err := ecdsa.Sign(notRandomReader, privateKey, signatureData)
	if err != nil {
		panic("Error generating signature: " + err.Error())
	}

	// Double checking
	hasher := sha256.New()
	hasher.Write(signatureData)

	fmt.Printf("\nStartHasher: %+v", hasher)
	fmt.Printf("\nStartHasherSum: %v", hasher.Sum(nil))

	fmt.Printf("\nStartSig R: %v\nStartSig S: %v", r, s)

	fmt.Printf("\nPublicKey Type: %T", privateKey.PublicKey)

	dsaSig := dsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("Error encoding signature: " + err.Error())
	}

	sigStr := encodeBase64(asnSig)

	pubkey := &ecdsa.PublicKey{
		Curve: privateKey.Curve,
		X:     big.NewInt(0).SetBytes(privateKey.PublicKey.X.Bytes()),
		Y:     big.NewInt(0).SetBytes(privateKey.PublicKey.Y.Bytes()),
	}

	type ECDSASignature struct {
		R, S *big.Int
	}
	//e := &ECDSASignature{}
	//h := sha256.New()
	//h.Write(signatureData)
	//if _, err := asn1.Unmarshal(asnSig, e); err != nil {
	//	panic("error unmarshalling signature: " + err.Error())
	//}
	//
	//isVerified := ecdsa.Verify(pubkey, h.Sum(nil), e.R, e.S)
	//fmt.Printf("\nisVerified: %v\n", IsVerified)
	//if !isVerified {
	//	panic("start sig is not verified")
	//}

	h := sha256.Sum256(signatureData)
	sig := &ECDSASignature{}

	if _, err = asn1.Unmarshal(asnSig, sig); err != nil {
		panic(err)
	}

	isVerified := ecdsa.Verify(pubkey, h[:], sig.R, sig.S)
	fmt.Printf("\nIsVerified: %v\n", isVerified)
	if !isVerified {
		panic("start sig is not verified")
	}

	return sigStr
}

func GenerateAuthenticationSigFromPrivateKey3(authData, clientData []byte, privateKey *ecdsa.PrivateKey) string {
	//clientDataHash := sha256.Sum256(p.Raw.AssertionResponse.ClientDataJSON)

	clientDataHash := sha256.Sum256(clientData)
	fmt.Printf("\nStartClientData: %v\nStartCDHash: %v\n", clientData, clientDataHash)
	signatureData := append(authData, clientDataHash[:]...)

	///////////////

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

	fmt.Printf("\nStart R: %v\nStart S: %v\n", r, s)

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	dsaSig := dsaSignature{R: r, S: s}

	asnSig, err := asn1.Marshal(dsaSig)
	if err != nil {
		panic("Error encoding signature: " + err.Error())
	}

	//sigStr := encodeBase64(asnSig)

	sigStr := base64.StdEncoding.EncodeToString(asnSig)

	isVerified := ecdsa.Verify(&publicKey, signhash, r, s)
	fmt.Printf("\nIsVerified: %v\n", isVerified)
	if !isVerified {
		panic("start sig is not verified")
	}

	///////
	// DOUBLE CHECKING
	VerifySignature(&publicKey, signatureData, asnSig)

	return sigStr
}

func VerifySignature(publicKey *ecdsa.PublicKey, data []byte, inSig []byte) {

	sigBytes := []byte(inSig)
	e := &dsaSignature{}
	var h hash.Hash
	h = sha256.New()
	h.Write(data)
	signHash := h.Sum(nil)

	_, err := asn1.Unmarshal(sigBytes, e)
	if err != nil {
		panic("error Unmarshalling signature: %s" + err.Error())
	}

	fmt.Printf("\nStart Sign Hash: %v\n", signHash)
	fmt.Printf("\nStart PublicKey: %+v\n", *publicKey)

	isVerified := ecdsa.Verify(publicKey, signHash, e.R, e.S)
	fmt.Printf("\nIsVerified: %v\n", isVerified)
	if !isVerified {
		panic("start sig is not verified")
	}

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

func GetBareAuthDataAndPrivateKey(appId, keyHandle string) (string, []byte, *ecdsa.PrivateKey) {

	buf := []byte{}
	// For our stuff add in the RP ID Hash (32 bytes)
	RPIDHash := sha256.Sum256([]byte(appId))
	for _, r := range RPIDHash {
		buf = append(buf, r)
	}

	// 65 = AT(64) + UP(1)
	// 193 = ED(128) + AT(64) + UP(1)
	// add a flag
	buf = append(buf, byte(65)) // ET flag

	// Add 4 bytes for counter = 0 (for now, just make it 0)
	buf = append(buf, []byte{byte(0), byte(0), byte(0), byte(0)}...)

	// Add 16 bytes for (zero) AAGUID
	aaguid := make([]byte, 16)
	buf = append(buf, aaguid...)

	credID := []byte(keyHandle)

	kHLen := len(keyHandle) // Must be less than 256
	idLen := []byte{byte(0), byte(kHLen)}

	buf = append(buf, idLen...)
	buf = append(buf, credID...)

	privateKey := GetPrivateKey()
	publicKey := privateKey.PublicKey

	pubKeyData := EC2PublicKeyData{
		PublicKeyData: PublicKeyData{
			Algorithm: int64(webauthncose.AlgES256),
			KeyType:   int64(webauthncose.EllipticKey),
		},
		XCoord: publicKey.X.Bytes(),
		YCoord: publicKey.Y.Bytes(),
	}

	// Copy it and see that it still has the same X and Y
	pubKey2 := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(publicKey.X.Bytes()),
		Y:     big.NewInt(0).SetBytes(publicKey.Y.Bytes()),
	}

	fmt.Printf("\nPublicKey Copy: %+v\n", pubKey2)

	fmt.Printf("\nStartPublicKeyAlgo: %v\n", pubKeyData.PublicKeyData.Algorithm)

	// Get the CBOR-encoded representation of the OKPPublicKeyData
	pubKeyBytes, err := webauthncbor.Marshal(pubKeyData)
	if err != nil {
		panic("error Marshaling publicKeyData: " + err.Error())
	}

	buf = append(buf, pubKeyBytes...)
	b64Buf := base64.RawURLEncoding.EncodeToString(buf)
	return b64Buf, buf, privateKey

}

func GetPublicKeyAsBytes(privateKey *ecdsa.PrivateKey) []byte {
	pubKey := privateKey.PublicKey
	gx := pubKey.Params().Gx
	gy := pubKey.Params().Gy

	fmt.Printf("\nStart PublicKey Gx: %v", gx.Bytes())
	fmt.Printf("\nStart PublicKey Gy: %v\n", gy.Bytes())

	buf := []byte{0x04} // Has to start with this, apparently
	buf = append(buf, pubKey.X.Bytes()...)
	buf = append(buf, pubKey.Y.Bytes()...)

	return buf
}
