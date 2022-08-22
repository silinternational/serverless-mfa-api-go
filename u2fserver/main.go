package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"

	mfa "github.com/silinternational/serverless-mfa-api-go"
	u2fsim "github.com/silinternational/serverless-mfa-api-go/u2fsimulator"
)

var (
	envConfig mfa.EnvConfig
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("U2f Simulator Server starting...")

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	log.Println("Starting service on port 8080")
	router := newRouter(nil)
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
	//   For information on this, see the doc comment for mfa.U2fRegistration
	{
		"RegistrationResponse",
		"POST",
		"/u2f/registration",
		u2fsim.U2fRegistration,
	},
}

// newRouter forms a new mux router, see https://github.com/gorilla/mux.
func newRouter(mws []mux.MiddlewareFunc) *mux.Router {
	// Create a basic router.
	router := mux.NewRouter().StrictSlash(true)

	// attach any extra middleware
	//for _, mw := range mws {
	//	router.Use(mw)
	//}

	// authenticate request based on api key and secret in headers
	// also adds user to context
	//router.Use(authenticationMiddleware)

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
