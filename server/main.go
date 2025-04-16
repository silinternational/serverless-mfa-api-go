package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

var envConfig mfa.EnvConfig

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Server starting...")

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatalf("error loading env vars: %s", err)
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	log.Println("Starting service on port 8080")
	router := newRouter()
	log.Fatal(http.ListenAndServe(":8080", router))
}

// route is used to pass information about a particular route.
type route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// Define our routes.
var routes = []route{
	{
		Name:        "CreateApiKey",
		Method:      "POST",
		Pattern:     "/api-key",
		HandlerFunc: mfa.CreateApiKey,
	},
	{
		Name:        "ActivateApiKey",
		Method:      "POST",
		Pattern:     "/api-key/activate",
		HandlerFunc: mfa.ActivateApiKey,
	},
	{
		Name:        "BeginRegistration",
		Method:      "POST",
		Pattern:     "/webauthn/register",
		HandlerFunc: mfa.BeginRegistration,
	},
	{
		Name:        "FinishRegistration",
		Method:      "PUT",
		Pattern:     "/webauthn/register",
		HandlerFunc: mfa.FinishRegistration,
	},
	{
		Name:        "BeginLogin",
		Method:      "POST",
		Pattern:     "/webauthn/login",
		HandlerFunc: mfa.BeginLogin,
	},
	{
		Name:        "FinishLogin",
		Method:      "PUT",
		Pattern:     "/webauthn/login",
		HandlerFunc: mfa.FinishLogin,
	},
	{
		Name:        "DeleteUser",
		Method:      "DELETE",
		Pattern:     "/webauthn/user",
		HandlerFunc: mfa.DeleteUser,
	},
	{ // This expects a path param that is the id that was previously returned
		// as the key_handle_hash from the FinishRegistration call.
		// Alternatively, if the id param indicates that a legacy U2F key should be removed
		//	 (e.g. by matching the string "u2f")
		//   then that user is saved with all of its legacy u2f fields blanked out.
		Name:        "DeleteCredential",
		Method:      "DELETE",
		Pattern:     fmt.Sprintf("/webauthn/credential/{%s}", mfa.IDParam),
		HandlerFunc: mfa.DeleteCredential,
	},
}

// newRouter forms a new mux router, see https://github.com/gorilla/mux.
func newRouter() *mux.Router {
	// Create a basic router.
	router := mux.NewRouter().StrictSlash(true)

	// authenticate request based on api key and secret in headers
	// also adds user to context
	router.Use(authenticationMiddleware)

	// add storage client to the request context
	router.Use(storageMiddleware)

	// Assign the handlers to run when endpoints are called.
	for _, route := range routes {
		router.Methods(route.Method).Path(route.Pattern).Name(route.Name).Handler(route.HandlerFunc)
	}

	router.NotFoundHandler = router.NewRoute().HandlerFunc(notFound).GetHandler()
	return router
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)

	notFound := map[string]string{
		"Method":     r.Method,
		"URL":        r.URL.String(),
		"RequestURI": r.RequestURI,
	}
	if err := json.NewEncoder(w).Encode(notFound); err != nil {
		log.Printf("ERROR could not marshal not found message to JSON: %s", err)
	}
}

// storageMiddleware initializes a storage client and adds it to the request context
func storageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storage, err := mfa.NewStorage(envConfig.AWSConfig)
		if err != nil {
			http.Error(w, fmt.Sprintf("error initializing storage: %s", err), http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), mfa.StorageContextKey, storage)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
