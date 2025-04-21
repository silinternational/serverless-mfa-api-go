package mfa

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

type User interface{}

// AuthenticateRequest checks the provided API key against the keys stored in the database. If the key is active and
// valid, a Webauthn client and WebauthnUser are created and stored in the request context.
func AuthenticateRequest(r *http.Request) (User, error) {
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

	err = apiKey.IsCorrect(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to validate api key: %w", err)
	}

	path := r.URL.Path
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch segments[0] {
	case "webauthn":
		return authWebauthnUser(r, localStorage, apiKey)

	case "totp":
		return nil, fmt.Errorf("TOTP is not yet supported")

	case "api-key":
		return nil, nil // no authentication required for api-key

	default:
		return nil, fmt.Errorf("invalid URL: %s", r.URL)
	}
}
