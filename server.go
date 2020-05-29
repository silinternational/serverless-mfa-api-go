package serverless_mfa_api_go

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
)

var (
	storage   *Storage
	envConfig EnvConfig
)

// EnvConfig holds environment specific configurations and is populated on init
type EnvConfig struct {
	ApiKeyTableName   string `json:"ApiKeyTableName"`
	WebAuthnTableName string `json:"WebAuthnTableName"`
	AWSConfig         *aws.Config
}

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

// Route is used to pass information about a particular route.
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// Routes is a slice of Route.
type Routes []Route

// Define our routes.
var routes = Routes{
	Route{
		"BeginRegistration",
		"POST",
		"/webauthn/register",
		BeginRegistration,
	},
	Route{
		"FinishRegistration",
		"PUT",
		"/webauthn/register",
		FinishRegistration,
	},
	Route{
		"BeginLogin",
		"POST",
		"/webauthn/login",
		BeginLogin,
	},
	Route{
		"FinishLogin",
		"PUT",
		"/webauthn/login",
		FinishLogin,
	},
}

// NewRouter forms a new mux router, see https://github.com/gorilla/mux.
func NewRouter(config EnvConfig, mws []mux.MiddlewareFunc) *mux.Router {
	envConfig = config

	// init storage from envConfig
	var err error
	storage, err = NewStorage(envConfig.AWSConfig)
	if err != nil {
		log.Printf("error initializing storage: %s", err.Error())
		os.Exit(1)
	}

	// Create a basic router.
	router := mux.NewRouter().StrictSlash(true)

	// attach any extra middleware
	for _, mw := range mws {
		router.Use(mw)
	}

	// authenticate request based on api key and secret in headers
	// also adds apiKey to context for help with encryption/decryption
	router.Use(AuthenticationMiddleware)

	// Assign the handlers to run when endpoints are called.
	for _, route := range routes {
		// Create a handler function.
		var handler http.Handler
		handler = route.HandlerFunc

		router.Methods(route.Method).Path(route.Pattern).Name(route.Name).Handler(handler)
	}

	router.NotFoundHandler = router.NewRoute().HandlerFunc(NotFound).GetHandler()
	return router
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		JSONResponse(w, err, http.StatusBadRequest)
	}

	options, err := user.BeginRegistration()
	if err != nil {
		JSONResponse(w, fmt.Sprintf("failed to begin registration: %s", err.Error()), http.StatusBadRequest)
		return
	}

	JSONResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		JSONResponse(w, err, http.StatusBadRequest)
		return
	}

	err = user.FinishRegistration(r)
	if err != nil {
		JSONResponse(w, err, http.StatusBadRequest)
		return
	}

	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		JSONResponse(w, err, http.StatusBadRequest)
		return
	}

	options, err := user.BeginLogin()
	if err != nil {
		JSONResponse(w, err, http.StatusBadRequest)
		return
	}

	JSONResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(r)
	if err != nil {
		JSONResponse(w, err, http.StatusBadRequest)
		return
	}

	credential, err := user.FinishLogin(r)
	if err != nil {
		JSONResponse(w, err, http.StatusBadRequest)
		return
	}

	resp := map[string]string{
		"credentialId": string(credential.ID),
	}

	JSONResponse(w, resp, http.StatusOK)
}

func NotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)

	notFound := map[string]string{
		"Method":     r.Method,
		"URL":        r.URL.String(),
		"RequestURI": r.RequestURI,
	}
	if err := json.NewEncoder(w).Encode(notFound); err != nil {
		log.Printf("%s: %s", "ERROR could not marshal not found message to JSON", err.Error())
	}
}

func JSONResponse(w http.ResponseWriter, body interface{}, status int) {
	jBody, err := json.Marshal(body)
	if err != nil {
		log.Printf("failed to marshal response body to json: %s\n", err.Error())
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s", jBody)
}

func fixEncoding(content []byte) (io.Reader, error) {
	allStr := string(content)
	allStr = strings.ReplaceAll(allStr, "+", "-")
	allStr = strings.ReplaceAll(allStr, "/", "_")
	allStr = strings.ReplaceAll(allStr, "=", "")

	return bytes.NewReader([]byte(allStr)), nil
}

func getWebAuthnFromApiMeta(config ApiMeta) (*webauthn.WebAuthn, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: config.RPDisplayName, // Display Name for your site
		RPID:          config.RPID,          // Generally the FQDN for your site
		RPOrigin:      config.RPOrigin,      // The origin URL for WebAuthn requests
		RPIcon:        config.RPIcon,        // Optional icon URL for your site
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

func getUserFromContext(r *http.Request) (DynamoUser, error) {
	user, ok := r.Context().Value("user").(DynamoUser)
	if !ok {
		return DynamoUser{}, errors.New("unable to get user from request context")
	}

	return user, nil
}
