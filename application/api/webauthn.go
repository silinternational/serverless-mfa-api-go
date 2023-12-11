package api

import "github.com/go-webauthn/webauthn/protocol"

// swagger:model
type WebAuthnBeginRegistrationOutput struct {
	ID string `json:"uuid"`
	protocol.CredentialCreation
}

// swagger:model
type WebAuthnFinishRegistrationOutput struct {
	KeyHandleHash string `json:"key_handle_hash"`
}

// swagger:model
type WebAuthnBeginLoginOutput protocol.CredentialAssertion

// swagger:model
type WebAuthnFinishLoginOutput struct {
	KeyHandleHash string `json:"key_handle_hash"`
}
