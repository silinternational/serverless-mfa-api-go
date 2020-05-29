package serverless_mfa_api_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/pkg/errors"
)

const WebAuthnTablePK = "uuid"

type DynamoUser struct {
	Store                *Storage              `json:"-"`
	SessionData          webauthn.SessionData  `json:"-"`
	EncryptedSessionData []byte                `json:"EncryptedSessionData,omitempty"`
	Credentials          []webauthn.Credential `json:"-"`
	EncryptedCredentials []byte                `json:"EncryptedCredentials,omitempty"`
	WebAuthnClient       *webauthn.WebAuthn    `json:"-"`
	ApiKey               ApiKey                `json:"-"`

	ID          string `json:"uuid"`
	APIKeyValue string `json:"apiKey"`
	Name        string `json:"-"`
	DisplayName string `json:"-"`
	Icon        string `json:"-"`
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
	_ = u.Load()
	return u
}

func (u *DynamoUser) unsetSessionData() error {
	u.EncryptedSessionData = nil
	return u.Store.Store(envConfig.WebAuthnTableName, u)
}

func (u *DynamoUser) saveSessionData(sessionData webauthn.SessionData) error {
	// load to be sure working with latest data
	err := u.Load()
	if err != nil {
		return err
	}

	js, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}

	enc, err := u.ApiKey.Encrypt(js)
	if err != nil {
		return err
	}

	u.EncryptedSessionData = enc
	return u.Store.Store(envConfig.WebAuthnTableName, u)
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

	return u.Store.Store(envConfig.WebAuthnTableName, u)
}

func (u *DynamoUser) Load() error {
	err := u.Store.Load(envConfig.WebAuthnTableName, WebAuthnTablePK, u.ID, u)
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
			return errors.Wrap(err, "failed to unmarshal session data")
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

func (u *DynamoUser) BeginRegistration() (*protocol.CredentialCreation, error) {
	options, sessionData, err := u.WebAuthnClient.BeginRegistration(u)
	if err != nil {
		return &protocol.CredentialCreation{}, fmt.Errorf("failed to begin registration: %w", err)
	}

	err = u.saveSessionData(*sessionData)
	if err != nil {
		return &protocol.CredentialCreation{}, fmt.Errorf("failed to save session data: %w", err)
	}

	return options, nil
}

func (u *DynamoUser) FinishRegistration(r *http.Request) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to get api config from request: %w", err)
	}

	br, err := fixEncoding(body)
	if err != nil {
		return fmt.Errorf("unable to fix encoding`: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(br)
	if err != nil {
		return fmt.Errorf("unable to parese credential creation response body`: %w", err)
	}

	credential, err := u.WebAuthnClient.CreateCredential(u, u.SessionData, parsedResponse)
	if err != nil {
		return fmt.Errorf("unable to create credential`: %w", err)
	}

	err = u.saveNewCredential(*credential)
	if err != nil {
		return fmt.Errorf("unable to save new credential`: %w", err)
	}

	return u.unsetSessionData()
}

func (u *DynamoUser) BeginLogin() (*protocol.CredentialAssertion, error) {
	options, sessionData, err := u.WebAuthnClient.BeginLogin(u)
	if err != nil {
		return &protocol.CredentialAssertion{}, err
	}

	err = u.saveSessionData(*sessionData)
	if err != nil {
		return &protocol.CredentialAssertion{}, err
	}

	return options, nil
}

func (u *DynamoUser) FinishLogin(r *http.Request) (*webauthn.Credential, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return &webauthn.Credential{}, fmt.Errorf("failed to read request bodyt: %w", err)
	}

	br, err := fixEncoding(body)
	if err != nil {
		return &webauthn.Credential{}, fmt.Errorf("failed to fix encoding in finish login: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(br)
	if err != nil {
		return &webauthn.Credential{}, fmt.Errorf("failed to parse credential request response body: %w", err)
	}

	credential, err := u.WebAuthnClient.ValidateLogin(u, u.SessionData, parsedResponse)
	if err != nil {
		return &webauthn.Credential{}, fmt.Errorf("failed to validate login: %w", err)
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

// Credentials owned by the user
func (u *DynamoUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
