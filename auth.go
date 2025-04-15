package mfa

import (
	"fmt"
	"log"
	"net/http"
)

// AuthenticateRequest checks the provided API key against the keys stored in the database. If the key is active and
// valid, a Webauthn client and WebauthnUser are created and stored in the request context.
func AuthenticateRequest(r *http.Request) (*WebauthnUser, error) {
	// get key and secret from headers
	key := r.Header.Get("x-mfa-apikey")
	secret := r.Header.Get("x-mfa-apisecret")

	if key == "" || secret == "" {
		return nil, fmt.Errorf("x-mfa-apikey and x-mfa-apisecret are required")
	}

	log.Printf("API called by key: %s. %s %s", key, r.Method, r.RequestURI)

	localStorage, err := NewStorage(envConfig.AWSConfig)
	if err != nil {
		return nil, fmt.Errorf("error initializing storage: %w", err)
	}

	apiKey := ApiKey{
		Key:    key,
		Secret: secret,
		Store:  localStorage,
	}

	err = apiKey.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load api key: %w", err)
	}

	if apiKey.ActivatedAt == 0 {
		return nil, fmt.Errorf("api call attempted for not yet activated key: %s", apiKey.Key)
	}

	valid, err := apiKey.IsCorrect(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to validate api key: %w", err)
	}

	if !valid {
		return nil, fmt.Errorf("invalid api secret for key %s", key)
	}

	// apiMeta includes info about the user and webauthn config
	apiMeta, err := getApiMetaFromRequest(r)
	if err != nil {
		log.Printf("unable to retrieve API meta information from request: %s", err)
		return nil, fmt.Errorf("unable to retrieve API meta information from request: %w", err)
	}

	webAuthnClient, err := getWebAuthnFromApiMeta(apiMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to create webauthn client from api meta config: %w", err)
	}

	user := NewWebauthnUser(apiMeta, localStorage, apiKey, webAuthnClient)

	// If this user exists (api key value is not empty), make sure the calling API Key owns the user and is allowed to operate on it
	if user.ApiKeyValue != "" && user.ApiKeyValue != apiKey.Key {
		log.Printf("api key %s tried to access user %s but that user does not belong to that api key", apiKey.Key, user.ID)
		return nil, fmt.Errorf("user does not exist")
	}

	return &user, nil
}
