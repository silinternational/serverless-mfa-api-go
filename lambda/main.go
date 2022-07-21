package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/kelseyhightower/envconfig"

	mfa "github.com/silinternational/serverless-mfa-api-go"
)

var envConfig mfa.EnvConfig

func init() {
	log.SetOutput(os.Stdout)

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatal(fmt.Errorf("error loading env vars: " + err.Error()))
	}
	envConfig.InitAWS()
}

func main() {
	log.SetOutput(os.Stdout)

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatal(fmt.Errorf("error loading env vars: " + err.Error()))
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	lambda.Start(handler)
}

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	r := httpRequestFromProxyRequest(ctx, req)
	user, err := mfa.AuthenticateRequest(r)
	if err != nil {
		return clientError(http.StatusUnauthorized, fmt.Sprintf("unable to authenticate request: %s", err))
	}

	// Add user into context for further use
	nctx := context.WithValue(r.Context(), mfa.UserContextKey, user)
	r = r.WithContext(nctx)

	// Use custom lambda http.ResponseWriter
	w := newLambdaResponseWriter()

	route := strings.ToLower(fmt.Sprintf("%s %s", req.HTTPMethod, req.Path))

	switch route {
	case "post /webauthn/login":
		mfa.BeginLogin(w, r)
	case "put /webauthn/login":
		mfa.FinishLogin(w, r)
	case "post /webauthn/register":
		mfa.BeginRegistration(w, r)
	case "put /webauthn/register":
		mfa.FinishRegistration(w, r)
	case "delete /webauthn/user":
		mfa.DeleteUser(w, r)
	// This expects a path param that is the id that was previously returned as
	//   the key_handle_hash from the FinishRegistration call.
	// Alternatively, if the id param indicates that a legacy U2F key should be removed
	//   (e.g. by matching the string "u2f")
	//   then that user is saved with all of its legacy u2f fields blanked out.
	case "delete /webauthn/credential":
		mfa.DeleteCredential(w, r)
	default:
		return clientError(http.StatusNotFound, fmt.Sprintf("The requested route is not supported: %s", route))
	}

	headers := map[string]string{}
	for k, v := range w.Header() {
		headers[k] = v[0]
	}

	return events.APIGatewayProxyResponse{
		StatusCode: w.Status,
		Headers:    headers,
		Body:       string(w.Body),
	}, nil
}

// clientError helper for send responses relating to client errors.
func clientError(status int, body string) (events.APIGatewayProxyResponse, error) {

	type cError struct {
		Error string
	}

	js, _ := json.Marshal(cError{Error: body})

	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       string(js),
	}, nil
}

func httpRequestFromProxyRequest(ctx context.Context, req events.APIGatewayProxyRequest) *http.Request {
	headers := http.Header{}
	for k, v := range req.Headers {
		headers.Set(k, v)
	}
	r := &http.Request{
		Method:        req.HTTPMethod,
		ProtoMinor:    0,
		Header:        headers,
		Body:          io.NopCloser(strings.NewReader(req.Body)),
		ContentLength: int64(len(req.Body)),
		RemoteAddr:    req.RequestContext.Identity.SourceIP,
		RequestURI:    req.Path,
	}
	return r.WithContext(ctx)
}
