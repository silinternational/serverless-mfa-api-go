package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

var (
	envConfig mfa.EnvConfig
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Server starting...")

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatal(fmt.Errorf("error loading env vars: " + err.Error()))
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	log.Println("Starting service on port 8080")
	router := newRouter([]mux.MiddlewareFunc{corsMiddleware})
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
		"BeginRegistration",
		"POST",
		"/webauthn/register",
		mfa.BeginRegistration,
	},
	{
		"FinishRegistration",
		"PUT",
		"/webauthn/register",
		mfa.FinishRegistration,
	},
	{
		"BeginLogin",
		"POST",
		"/webauthn/login",
		mfa.BeginLogin,
	},
	{
		"FinishLogin",
		"PUT",
		"/webauthn/login",
		mfa.FinishLogin,
	},
	{
		"DeleteUser",
		"DELETE",
		"/webauthn/user",
		mfa.DeleteUser,
	},
	{ // This expects a query string param like `?credential-id=<hashed-encoded-credential-id>
		// where the id was previously returned as the key_handle_hash from the FinishRegistration call
		"DeleteCredential",
		"DELETE",
		"/webauthn/credential",
		mfa.DeleteCredential,
	},
}

// newRouter forms a new mux router, see https://github.com/gorilla/mux.
func newRouter(mws []mux.MiddlewareFunc) *mux.Router {
	// Create a basic router.
	router := mux.NewRouter().StrictSlash(true)

	// attach any extra middleware
	for _, mw := range mws {
		router.Use(mw)
	}

	// authenticate request based on api key and secret in headers
	// also adds user to context
	router.Use(authenticationMiddleware)

	// Assign the handlers to run when endpoints are called.
	for _, route := range routes {
		// Create a handler function.
		var handler http.Handler
		handler = route.HandlerFunc

		router.Methods(route.Method).Path(route.Pattern).Name(route.Name).Handler(handler)
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
		log.Printf("ERROR could not marshal not found message to JSON: %s", err.Error())
	}
}
