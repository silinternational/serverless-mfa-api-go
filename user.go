package mfa

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/duo-labs/webauthn/webauthn"
)

const (
	UserContextKey  = "user"
	WebAuthnTablePK = "uuid"
)

type DynamoUser struct {
	// Shared fields between U2F and WebAuthn
	ID          string   `json:"uuid"`
	APIKeyValue string   `json:"apiKey"`
	ApiKey      ApiKey   `json:"-"`
	Store       *Storage `json:"-"`

	// U2F fields
	AppId              string `json:"-"`
	EncryptedAppId     string `json:"encryptedAppId,omitempty"`
	KeyHandle          string `json:"-"`
	EncryptedKeyHandle string `json:"encryptedKeyHandle,omitempty"`
	PublicKey          string `json:"-"`
	EncryptedPublicKey string `json:"encryptedPublicKey,omitempty"`

	// WebAuthn fields
	SessionData          webauthn.SessionData  `json:"-"`
	EncryptedSessionData []byte                `json:"EncryptedSessionData,omitempty"`
	Credentials          []webauthn.Credential `json:"-"`
	EncryptedCredentials []byte                `json:"EncryptedCredentials,omitempty"`
	WebAuthnClient       *webauthn.WebAuthn    `json:"-"`
	Name                 string                `json:"-"`
	DisplayName          string                `json:"-"`
	Icon                 string                `json:"-"`
}

func NewDynamoUser(apiConfig ApiMeta, storage *Storage, apiKey ApiKey, webAuthnClient *webauthn.WebAuthn) DynamoUser {
	u := DynamoUser{
		ID:             apiConfig.UserUUID,
		Name:           apiConfig.Username,
		DisplayName:    apiConfig.UserDisplayName,
		Icon:           apiConfig.UserIcon,
		Store:          storage,
		WebAuthnClient: webAuthnClient,
		ApiKey:         apiKey,
		APIKeyValue:    apiKey.Key,
	}

	if u.ID == "" {
		return u
	}

	err := u.Load()
	if err != nil {
		log.Printf("failed to load user: %s\n", err)
	}
	return u
}

func (u *DynamoUser) unsetSessionData() error {
	u.EncryptedSessionData = nil
	return u.Store.Store(envConfig.WebauthnTable, u)
}

func (u *DynamoUser) saveSessionData(sessionData webauthn.SessionData) error {
	// load to be sure working with latest data
	err := u.Load()
	if err != nil {
		return err
	}

	js, err := json.Marshal(sessionData)
	if err != nil {
		log.Printf("error marshaling session data to json. Session data: %+v\n Error: %s\n", sessionData, err)
		return err
	}

	enc, err := u.ApiKey.Encrypt(js)
	if err != nil {
		return err
	}

	u.EncryptedSessionData = enc
	return u.Store.Store(envConfig.WebauthnTable, u)
}

func (u *DynamoUser) saveNewCredential(credential webauthn.Credential) error {
	// load to be sure working with latest data
	err := u.Load()
	if err != nil {
		return err
	}

	// check existing credentials to make sure this one doesn't already exist
	for _, c := range u.Credentials {
		if string(c.ID) == string(credential.ID) {
			return fmt.Errorf("a credential with this ID already exists")
		}
	}

	// append new credential to existing
	u.Credentials = append(u.Credentials, credential)

	// encrypt credentials for storage
	js, err := json.Marshal(u.Credentials)
	if err != nil {
		return err
	}

	enc, err := u.ApiKey.Encrypt(js)
	if err != nil {
		return err
	}
	u.EncryptedCredentials = enc

	return u.Store.Store(envConfig.WebauthnTable, u)
}

func (u *DynamoUser) Load() error {
	err := u.Store.Load(envConfig.WebauthnTable, WebAuthnTablePK, u.ID, u)
	if err != nil {
		return errors.Wrap(err, "failed to load user")
	}

	// decrypt SessionStorage if available
	if len(u.EncryptedSessionData) > 0 {
		plain, err := u.ApiKey.Decrypt(u.EncryptedSessionData)
		if err != nil {
			return errors.Wrap(err, "failed to decrypt encrypted session data")
		}

		// decryption process includes extra/invalid \x00 character, so trim it out
		plain = bytes.Trim(plain, "\x00")

		// unmarshal decrypted session data into SessionData
		var sd webauthn.SessionData
		err = json.Unmarshal(plain, &sd)
		if err != nil {
			log.Printf("failed to unmarshal encrypted session data, will discard and continue. error: %s", err)
		}

		u.SessionData = sd
	}

	// decrypt Credentials if available
	if len(u.EncryptedCredentials) > 0 {
		dec, err := u.ApiKey.Decrypt(u.EncryptedCredentials)
		if err != nil {
			return errors.Wrap(err, "failed to decrypt encrypted credential data")
		}

		// decryption process includes extra/invalid \x00 character, so trim it out
		dec = bytes.Trim(dec, "\x00")

		// unmarshal decrypted session data into Credentials
		var creds []webauthn.Credential
		err = json.Unmarshal(dec, &creds)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal credential data")
		}
		u.Credentials = creds
	}

	return nil
}

func (u *DynamoUser) Delete() error {
	return u.Store.Delete(envConfig.WebauthnTable, WebAuthnTablePK, u.ID)
}

func (u *DynamoUser) BeginRegistration() (*protocol.CredentialCreation, error) {
	if u.WebAuthnClient == nil {
		return nil, fmt.Errorf("dynamoUser, %s, missing WebAuthClient in BeginRegistration", u.Name)
	}

	rrk := false
	authSelection := protocol.AuthenticatorSelection{
		RequireResidentKey: &rrk,
		UserVerification:   protocol.VerificationDiscouraged,
	}

	options, sessionData, err := u.WebAuthnClient.BeginRegistration(u, webauthn.WithAuthenticatorSelection(authSelection))
	if err != nil {
		return &protocol.CredentialCreation{}, fmt.Errorf("failed to begin registration: %w", err)
	}

	err = u.saveSessionData(*sessionData)
	if err != nil {
		return &protocol.CredentialCreation{}, fmt.Errorf("failed to save session data: %w", err)
	}

	return options, nil
}

func (u *DynamoUser) FinishRegistration(r *http.Request) (string, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("failed to get api config from request: %w", err)
	}

	br := fixEncoding(body)
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(br)
	if err != nil {
		return "", fmt.Errorf("unable to parese credential creation response body`: %w", err)
	}

	credential, err := u.WebAuthnClient.CreateCredential(u, u.SessionData, parsedResponse)
	if err != nil {
		return "", fmt.Errorf("unable to create credential`: %w", err)
	}

	err = u.saveNewCredential(*credential)
	if err != nil {
		return "", fmt.Errorf("unable to save new credential`: %w", err)
	}

	keyHandleHash := hashAndEncodeKeyHandle(credential.ID)

	return keyHandleHash, u.unsetSessionData()
}

func (u *DynamoUser) BeginLogin() (*protocol.CredentialAssertion, error) {
	extensions := protocol.AuthenticationExtensions{}
	if u.EncryptedAppId != "" {
		appid, err := u.ApiKey.DecryptLegacy([]byte(u.EncryptedAppId))
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt legacy app id: %s", err)
		}
		extensions["appid"] = string(appid)
	}

	options, sessionData, err := u.WebAuthnClient.BeginLogin(u, webauthn.WithAssertionExtensions(extensions), webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		return &protocol.CredentialAssertion{}, err
	}

	err = u.saveSessionData(*sessionData)
	if err != nil {
		log.Printf("error saving session data: %s\n", err)
		return nil, err
	}

	return options, nil
}

func (u *DynamoUser) FinishLogin(r *http.Request) (*webauthn.Credential, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("failed to read request bodyt: %s", err)
		return &webauthn.Credential{}, fmt.Errorf("failed to read request bodyt: %s", err)
	}

	br := fixEncoding(body)
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(br)
	if err != nil {
		log.Printf("failed to parse credential request response body: %s", err)
		return &webauthn.Credential{}, fmt.Errorf("failed to parse credential request response body: %s", err)
	}

	// If user has registered U2F creds, check if RPIDHash is actually hash of AppId
	// if so, replace authenticator data RPIDHash with a hash of the RPID for validation
	if u.EncryptedAppId != "" {
		appid, err := u.ApiKey.DecryptLegacy([]byte(u.EncryptedAppId))
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt legacy app id: %s", err)
		}

		appIdHash := sha256.Sum256([]byte(appid))
		rpIdHash := sha256.Sum256([]byte(u.WebAuthnClient.Config.RPID))

		if fmt.Sprintf("%x", parsedResponse.Response.AuthenticatorData.RPIDHash) == fmt.Sprintf("%x", appIdHash) {
			parsedResponse.Response.AuthenticatorData.RPIDHash = rpIdHash[:]
		}
	}

	// there is an issue with URLEncodeBase64.UnmarshalJSON and null values
	// see https://github.com/duo-labs/webauthn/issues/69
	// null byte sequence is []byte{158,233,101}
	if isNullByteSlice(parsedResponse.Response.UserHandle) {
		parsedResponse.Response.UserHandle = nil
	}

	credential, err := u.WebAuthnClient.ValidateLogin(u, u.SessionData, parsedResponse)
	if err != nil {
		log.Printf("failed to validate login: %s", err)
		return &webauthn.Credential{}, fmt.Errorf("failed to validate login: %s", err)
	}

	return credential, nil
}

// User ID according to the Relying Party
func (u *DynamoUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

// User Name according to the Relying Party
func (u *DynamoUser) WebAuthnName() string {
	return u.Name
}

// Display Name of the user
func (u *DynamoUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// User's icon url
func (u *DynamoUser) WebAuthnIcon() string {
	return u.Icon
}

// WebAuthnCredentials returns an array of credentials plus a U2F cred if present
func (u *DynamoUser) WebAuthnCredentials() []webauthn.Credential {
	creds := u.Credentials

	if u.EncryptedKeyHandle != "" && u.EncryptedPublicKey != "" {
		credId, err := u.ApiKey.DecryptLegacy([]byte(u.EncryptedKeyHandle))
		if err != nil {
			log.Printf("unable to decrypt credential id: %s", err)
			return nil
		}

		// decryption process includes extra/invalid \x00 character, so trim it out
		// at some point early in dev this was needed, but in testing recently it doesn't
		// make a difference. Leaving commented out for now until we know 100% it's not needed
		//credId = bytes.Trim(credId, "\x00")

		decodedCredId, err := base64.RawURLEncoding.DecodeString(string(credId))
		if err != nil {
			log.Println("error decoding credential id:", err)
			return nil
		}

		pubKey, err := u.ApiKey.DecryptLegacy([]byte(u.EncryptedPublicKey))
		if err != nil {
			log.Printf("unable to decrypt pubic key: %s", err)
			return nil
		}
		// Same as credId
		//pubKey = bytes.Trim(pubKey, "\x00")

		decodedPubKey, err := base64.RawURLEncoding.DecodeString(string(pubKey))
		if err != nil {
			log.Println("error decoding public key:", err)
			return nil
		}

		// U2F key is concatenation of 0x4 + Xcoord + Ycoord
		// documentation / example at https://docs.yubico.com/yesdk/users-manual/application-piv/attestation.html
		coordLen := (len(decodedPubKey) - 1) / 2
		xCoord := decodedPubKey[1 : coordLen+1]
		yCoord := decodedPubKey[1+coordLen:]

		ec2PublicKey := webauthncose.EC2PublicKeyData{
			XCoord: xCoord,
			YCoord: yCoord,
			PublicKeyData: webauthncose.PublicKeyData{
				Algorithm: int64(webauthncose.AlgES256),
				KeyType:   int64(webauthncose.EllipticKey),
			},
		}

		// Get the CBOR-encoded representation of the OKPPublicKeyData
		cborEncodedKey, err := cbor.Marshal(ec2PublicKey)
		if err != nil {
			log.Printf("error marshalling key to cbor: %s", err)
			return nil
		}

		creds = append(creds, webauthn.Credential{
			ID:              decodedCredId,
			PublicKey:       cborEncodedKey,
			AttestationType: string(protocol.PublicKeyCredentialType),
		})
	}

	return creds
}

// isNullByteSlice works around a bug in json unmarshalling for a urlencoded base64 string
func isNullByteSlice(slice []byte) bool {
	if len(slice) != 3 {
		return false
	}
	if slice[0] == 158 && slice[1] == 233 && slice[2] == 101 {
		return true
	}
	return false
}

func hashAndEncodeKeyHandle(id []byte) string {
	hash := sha256.Sum256(id)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
