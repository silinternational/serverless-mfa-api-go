package mfa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/duo-labs/webauthn/webauthn"
)

// ApiMeta holds metadata about the calling service for use in WebAuthn responses.
// Since this service/api is consumed by multiple sources this information cannot
// be stored in the envConfig
type ApiMeta struct {
	RPDisplayName   string `json:"RPDisplayName"` // Display Name for your site
	RPID            string `json:"RPID"`          // Generally the FQDN for your site
	RPOrigin        string `json:"RPOrigin"`      // The origin URL for WebAuthn requests
	RPIcon          string `json:"RPIcon"`        // Optional icon URL for your site
	UserUUID        string `json:"UserUUID"`
	Username        string `json:"Username"`
	UserDisplayName string `json:"UserDisplayName"`
	UserIcon        string `json:"UserIcon"`
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
	}

	options, err := user.BeginRegistration()
	if err != nil {
		jsonResponse(w, fmt.Sprintf("failed to begin registration: %s", err.Error()), http.StatusBadRequest)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		return
	}

	err = user.FinishRegistration(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		return
	}

	jsonResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	options, err := user.BeginLogin()
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error beginning user login: %s\n", err)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	credential, err := user.FinishLogin(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error finishing user login	: %s\n", err)
		return
	}

	resp := map[string]string{
		"credentialId": string(credential.ID),
	}

	jsonResponse(w, resp, http.StatusOK)
}

func jsonResponse(w http.ResponseWriter, body interface{}, status int) {
	jBody, err := json.Marshal(body)
	if err != nil {
		log.Printf("failed to marshal response body to json: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("failed to marshal response body to json"))
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(jBody)
	if err != nil {
		log.Printf("faild to write response in jsonResponse: %s\n", err)
	}
}

func fixEncoding(content []byte) (io.Reader, error) {
	allStr := string(content)
	allStr = strings.ReplaceAll(allStr, "+", "-")
	allStr = strings.ReplaceAll(allStr, "/", "_")
	allStr = strings.ReplaceAll(allStr, "=", "")

	return bytes.NewReader([]byte(allStr)), nil
}

func getWebAuthnFromApiMeta(meta ApiMeta) (*webauthn.WebAuthn, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: meta.RPDisplayName, // Display Name for your site
		RPID:          meta.RPID,          // Generally the FQDN for your site
		RPOrigin:      meta.RPOrigin,      // The origin URL for WebAuthn requests
		RPIcon:        meta.RPIcon,        // Optional icon URL for your site
		Debug:         true,
	})
	if err != nil {
		fmt.Println(err)
	}

	return web, nil
}

func getApiMetaFromRequest(r *http.Request) (ApiMeta, error) {
	meta := ApiMeta{
		RPDisplayName:   r.Header.Get("x-mfa-RPDisplayName"),
		RPID:            r.Header.Get("x-mfa-RPID"),
		RPOrigin:        r.Header.Get("x-mfa-RPOrigin"),
		RPIcon:          r.Header.Get("x-mfa-RPIcon"),
		UserUUID:        r.Header.Get("x-mfa-UserUUID"),
		Username:        r.Header.Get("x-mfa-Username"),
		UserDisplayName: r.Header.Get("x-mfa-UserDisplayName"),
		UserIcon:        r.Header.Get("x-mfa-UserIcon"),
	}

	// check that required fields are provided
	if meta.RPDisplayName == "" {
		msg := "missing required header: x-mfa-RPDisplayName"
		return ApiMeta{}, fmt.Errorf(msg)
	}
	if meta.RPID == "" {
		msg := "missing required header: x-mfa-RPID"
		return ApiMeta{}, fmt.Errorf(msg)
	}
	if meta.RPOrigin == "" {
		msg := "missing required header: x-mfa-RPOrigin"
		return ApiMeta{}, fmt.Errorf(msg)
	}
	if meta.UserUUID == "" {
		msg := "missing required header: x-mfa-UserUUID"
		return ApiMeta{}, fmt.Errorf(msg)
	}
	if meta.Username == "" {
		msg := "missing required header: x-mfa-Username"
		return ApiMeta{}, fmt.Errorf(msg)
	}
	if meta.UserDisplayName == "" {
		msg := "missing required header: x-mfa-UserDisplayName"
		return ApiMeta{}, fmt.Errorf(msg)
	}

	return meta, nil
}

func getUserFromContext(r *http.Request) (*DynamoUser, error) {
	user, ok := r.Context().Value(UserContextKey).(*DynamoUser)
	if !ok {
		return &DynamoUser{}, errors.New("unable to get user from request context")
	}

	return user, nil
}

func AuthenticateRequest(r *http.Request) (*DynamoUser, error) {
	// get key and secret from headers
	key := r.Header.Get("x-mfa-key")
	secret := r.Header.Get("x-mfa-secret")

	if key == "" || secret == "" {
		return nil, fmt.Errorf("x-mfa-key and x-mfa-secret are required")
	}

	log.Printf("API called by key: %s. %s %s", key, r.Method, r.RequestURI)

	localStorage, err := NewStorage(envConfig.AWSConfig)
	if err != nil {
		return nil, fmt.Errorf("error initializing storage: %s", err.Error())
	}

	apiKey := ApiKey{
		Key:    key,
		Secret: secret,
		Store:  localStorage,
	}

	err = apiKey.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load api key: %s", err.Error())
	}

	if apiKey.ActivatedAt == 0 {
		return nil, fmt.Errorf("api call attempted for not yet activated key: %s", apiKey.Key)
	}

	valid, err := apiKey.IsCorrect(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to validate api key: %s", err.Error())
	}

	if !valid {
		return nil, fmt.Errorf("invalid api secret for key %s: %s", key, err.Error())
	}

	// apiMeta includes info about the user and webauthn config
	apiMeta, err := getApiMetaFromRequest(r)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve api meta information from request: %s", err.Error())
	}

	webAuthnClient, err := getWebAuthnFromApiMeta(apiMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to create webauthn client from api meta config: %s", err.Error())
	}

	user := NewDynamoUser(apiMeta, localStorage, apiKey, webAuthnClient)

	// If this user exists (api key value is not empty), make sure the calling API Key owns the user and is allowed to operate on it
	if user.APIKeyValue != "" && user.APIKeyValue != apiKey.Key {
		log.Printf("api key %s tried to access user %s but that user does not belong to that api key", apiKey.Key, user.ID)
		return nil, fmt.Errorf("user does not exist")
	}

	return &user, nil
}
