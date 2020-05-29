package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/gorilla/mux"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

func main() {
	envConfig := mfa.EnvConfig{
		ApiKeyTableName:   os.Getenv("API_KEY_TABLE"),
		WebAuthnTableName: os.Getenv("WEBAUTHN_TABLE"),
		AWSConfig: &aws.Config{
			Endpoint:   aws.String(os.Getenv("AWS_ENDPOINT")),
			Region:     aws.String(os.Getenv("AWS_DEFAULT_REGION")),
			DisableSSL: aws.Bool(getEnvAsBool("AWS_DISABLE_SSL")),
		},
	}
	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	log.Println("Starting service on port 8080")
	router := mfa.NewRouter(envConfig, []mux.MiddlewareFunc{CorsMiddleware})
	log.Fatal(http.ListenAndServe(":8080", router))
}

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "POST, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func getEnvAsBool(name string) bool {
	val := os.Getenv(name)
	if strings.ToLower(val) == "true" {
		return true
	}
	return false
}
