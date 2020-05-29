package serverless_mfa_api_go

import (
	"context"
	"log"
	"net/http"
	"os"
)

// AuthenticationMiddleware gets API key information from request headers and validates the key/signature
// Then it uses api meta information provided in headers to configure a webauthn client and fetch the
// user from storage and attach to context.
func AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get key and secret from headers
		key := r.Header.Get("x-mfa-key")
		secret := r.Header.Get("x-mfa-secret")

		if key == "" || secret == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}

		log.Printf("API called by key: %s. %s %s", key, r.Method, r.RequestURI)

		localStorage, err := NewStorage(envConfig.AWSConfig)
		if err != nil {
			log.Printf("error initializing storage: %s", err.Error())
			os.Exit(1)
		}

		apiKey := ApiKey{
			Key:    key,
			Secret: secret,
			Store:  localStorage,
		}

		err = apiKey.Load()
		if err != nil {
			log.Printf("failed to load api key: %s", err.Error())
			http.Error(w, "Forbidden", http.StatusForbidden)
		}

		if apiKey.ActivatedAt == 0 {
			log.Printf("api call attempted for not yet activated key: %s", apiKey.Key)
			http.Error(w, "Forbidden", http.StatusForbidden)
		}

		valid, err := apiKey.IsCorrect(secret)
		if err != nil {
			log.Printf("failed to validate api key: %s", err.Error())
			http.Error(w, "Forbidden", http.StatusForbidden)
		}

		if !valid {
			log.Printf("invalid api secret for key %s: %s", key, err.Error())
			http.Error(w, "Forbidden", http.StatusForbidden)
		}

		// apiMeta includes info about the user and webauthn config
		apiMeta, err := getApiMetaFromRequest(r)
		if err != nil {
			log.Printf("unable to retrieve api meta information from request: %s", err.Error())
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}

		webAuthnClient, err := getWebAuthnFromApiMeta(apiMeta)
		if err != nil {
			log.Printf("unable to create webauthn client from api meta config: %s", err.Error())
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}

		user := NewDynamoUser(apiMeta, storage, apiKey, webAuthnClient)

		// If this user exists (api key value is not empty), make sure the calling API Key owns the user and is allowed to operate on it
		if user.APIKeyValue != "" && user.APIKeyValue != apiKey.Key {
			log.Printf("api key %s tried to access user %s but that user does not belong to that api key", apiKey.Key, user.ID)
			http.Error(w, "Forbidden", http.StatusForbidden)
		}

		// Add apiKey into context for further use
		ctx := context.WithValue(r.Context(), "user", user)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
