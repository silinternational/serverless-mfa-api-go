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

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
)

const IDParam = "id"

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

// beginRegistrationResponse adds uuid to response for consumers that depend on this api to generate the uuid
type beginRegistrationResponse struct {
	UUID string `json:"uuid"`
	protocol.CredentialCreation
}

type finishRegistrationResponse struct {
	KeyHandleHash string `json:"key_handle_hash"`
}

type finishLoginResponse struct {
	CredentialID  string `json:"credentialId"` // DEPRECATED, use KeyHandleHash instead
	KeyHandleHash string `json:"key_handle_hash"`
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
	}

	// If user.id is empty, treat as new user/registration
	if user.ID == "" {
		user.ID = uuid.NewV4().String()
	}

	options, err := user.BeginRegistration()
	if err != nil {
		jsonResponse(w, fmt.Sprintf("failed to begin registration: %s", err.Error()), http.StatusBadRequest)
		return
	}

	response := beginRegistrationResponse{
		user.ID,
		*options,
	}

	jsonResponse(w, response, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		return
	}

	keyHandleHash, err := user.FinishRegistration(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		return
	}

	response := finishRegistrationResponse{
		KeyHandleHash: keyHandleHash,
	}

	jsonResponse(w, response, http.StatusOK) // Handle next steps
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

	resp := finishLoginResponse{
		CredentialID:  string(credential.ID),
		KeyHandleHash: hashAndEncodeKeyHandle(credential.ID),
	}

	jsonResponse(w, resp, http.StatusOK)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	if err := user.Delete(); err != nil {
		jsonResponse(w, err, http.StatusInternalServerError)
		log.Printf("error deleting user: %s", err)
		return
	}

	jsonResponse(w, nil, http.StatusNoContent)
}

func DeleteCredential(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("error getting user from context: %s\n", err)
		return
	}

	params := mux.Vars(r)
	credID, ok := params[IDParam]
	if !ok || credID == "" {
		err := fmt.Errorf("%s path parameter not provided to DeleteCredential", IDParam)
		jsonResponse(w, err, http.StatusBadRequest)
		log.Printf("%s\n", err)
		return
	}

	status, err := user.DeleteCredential(credID)
	if err != nil {
		log.Printf("error deleting user credential: %s", err)
	}

	jsonResponse(w, err, status)
}

type simpleError struct {
	Error string `json:"error"`
}

func newSimpleError(err error) simpleError {
	return simpleError{Error: err.Error()}
}

func jsonResponse(w http.ResponseWriter, body interface{}, status int) {
	var data interface{}
	switch b := body.(type) {
	case error:
		data = newSimpleError(b)
	default:
		data = body
	}

	jBody := []byte{}
	var err error
	if data != nil {
		jBody, err = json.Marshal(data)
		if err != nil {
			log.Printf("failed to marshal response body to json: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to marshal response body to json"))
			return
		}
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(jBody)
	if err != nil {
		log.Printf("faild to write response in jsonResponse: %s\n", err)
	}
}

func fixStringEncoding(content string) string {
	content = strings.ReplaceAll(content, "+", "-")
	content = strings.ReplaceAll(content, "/", "_")
	content = strings.ReplaceAll(content, "=", "")
	return content
}

func fixEncoding(content []byte) io.Reader {
	allStr := string(content)
	return bytes.NewReader([]byte(fixStringEncoding(allStr)))
}

func getWebAuthnFromApiMeta(meta ApiMeta) (*webauthn.WebAuthn, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: meta.RPDisplayName,      // Display Name for your site
		RPID:          meta.RPID,               // Generally the FQDN for your site
		RPOrigins:     []string{meta.RPOrigin}, // The origin URL for WebAuthn requests
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
	key := r.Header.Get("x-mfa-apikey")
	secret := r.Header.Get("x-mfa-apisecret")

	if key == "" || secret == "" {
		return nil, fmt.Errorf("x-mfa-apikey and x-mfa-apisecret are required")
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
		msg := fmt.Sprintf("unable to retrieve api meta information from request: %s", err.Error())
		log.Println(msg)
		return nil, fmt.Errorf(msg)
	}

	webAuthnClient, err := getWebAuthnFromApiMeta(apiMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to create webauthn client from api meta config: %s", err.Error())
	}

	user := NewDynamoUser(apiMeta, localStorage, apiKey, webAuthnClient)

	// If this user exists (api key value is not empty), make sure the calling API Key owns the user and is allowed to operate on it
	if user.ApiKeyValue != "" && user.ApiKeyValue != apiKey.Key {
		log.Printf("api key %s tried to access user %s but that user does not belong to that api key", apiKey.Key, user.ID)
		return nil, fmt.Errorf("user does not exist")
	}

	return &user, nil
}
