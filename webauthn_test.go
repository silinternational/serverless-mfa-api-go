package mfa

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

type lambdaResponseWriter struct {
	Body    []byte
	Headers http.Header
	Status  int
}

func newLambdaResponseWriter() *lambdaResponseWriter {
	return &lambdaResponseWriter{
		Headers: http.Header{},
	}
}

func (l *lambdaResponseWriter) Header() http.Header {
	return l.Headers
}

func (l *lambdaResponseWriter) Write(contents []byte) (int, error) {
	// If WriteHeader has not been called, Write is supposed to set default status code
	if l.Status == 0 {
		l.Status = http.StatusOK
	}

	l.Body = append(l.Body, contents...)
	return len(l.Body), nil
}

func (l *lambdaResponseWriter) WriteHeader(statusCode int) {
	l.Status = statusCode
}

func Test_Parse(t *testing.T) {
	body := `{"rawId":"kCvEeC0h5T4cmnggaesuj2rpiOloBbtRMuGhBUEHmAOHDTPW9pf5ZkXZtm8OQ7HSYT6XnL0W21rrLvWaVGSzag==","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEd/SocWgnCorN52AiYfEj3abYOxgwLEwK3G2/Pk5e83NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQJArxHgtIeU+HJp4IGnrLo9q6YjpaAW7UTLhoQVBB5gDhw0z1vaX+WZF2bZvDkOx0mE+l5y9Ftta6y71mlRks2qlAQIDJiABIVggEroUOB+o5SMLdlfIH1E/UJ8sB3sQkrkGpQlo5BSvh+MiWCDnPHY/oEFqXtlAjZTfIPkUCeamWxhHFwLDlplmfccx4w==","getTransports":{},"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJkNWtidXR6MHhSMEJUVkc0eUpWRjRBbHNTZjBSUTFCcGVYSlQwQmtQY3RBIiwiZXh0cmFfa2V5c19tYXlfYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Lmd0aXMuZ3VydSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ=="},"getClientExtensionResults":{},"id":"kCvEeC0h5T4cmnggaesuj2rpiOloBbtRMuGhBUEHmAOHDTPW9pf5ZkXZtm8OQ7HSYT6XnL0W21rrLvWaVGSzag","type":"public-key"}`

	newReader := fixEncoding([]byte(body))

	_, err := protocol.ParseCredentialCreationResponseBody(newReader)
	if err != nil {
		t.Errorf("error: %+v", err)
	}
}

func Test_BeginLogin(t *testing.T) {
	assert := require.New(t)

	err := initDb()
	if err != nil {
		t.Error(err)
		return
	}
	awsConfig := aws.Config{
		Endpoint:   aws.String(os.Getenv("AWS_ENDPOINT")),
		Region:     aws.String(os.Getenv("AWS_DEFAULT_REGION")),
		DisableSSL: aws.Bool(true),
	}

	envCfg := EnvConfig{
		ApiKeyTable:      "api_keys",
		WebauthnTable:    "WebAuthn",
		AwsEndpoint:      os.Getenv("AWS_ENDPOINT"),
		AwsDefaultRegion: os.Getenv("AWS_DEFAULT_REGION"),
		AwsDisableSSL:    true,
		AWSConfig:        &awsConfig,
	}

	SetConfig(envCfg)

	localStorage, err := NewStorage(&awsConfig)
	assert.NoError(err, "failed creating local storage for test")

	aKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	aSec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := ApiKey{
		Key:    aKey,
		Secret: aSec,
		Store:  localStorage,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",   // Display Name for your site
		RPID:          "111.11.11.11", // Generally the FQDN for your site
		Debug:         true,
	})

	assert.NoError(err, "failed creating new webAuthnClient for test")

	userNoCreds := DynamoUser{
		ID:             "",
		Name:           "Nelly_NoCredentials",
		DisplayName:    "Nelly NoCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		APIKeyValue:    apiKey.Key,
	}

	userID := "12345678-1234-1234-1234-123456789012"
	userIDEncoded := base64.StdEncoding.EncodeToString([]byte(userID))

	creds := []webauthn.Credential{
		{
			ID:        []byte(userID),
			PublicKey: []byte("1234"),
		},
	}

	userWithCreds := DynamoUser{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		APIKeyValue:    apiKey.Key,
		Credentials:    creds,
	}

	reqWithUserNoCredentials := http.Request{}
	ctxWithUser := context.WithValue(reqWithUserNoCredentials.Context(), UserContextKey, &userNoCreds)
	reqWithUserNoCredentials = *reqWithUserNoCredentials.WithContext(ctxWithUser)

	reqWithUserCredentials := http.Request{}
	ctxWithUserCredentials := context.WithValue(reqWithUserCredentials.Context(), UserContextKey, &userWithCreds)
	reqWithUserCredentials = *reqWithUserCredentials.WithContext(ctxWithUserCredentials)

	localStorage.Store(envConfig.WebauthnTable, ctxWithUserCredentials)

	tests := []struct {
		name             string
		httpWriter       *lambdaResponseWriter
		httpReq          http.Request
		wantBodyContains []string
	}{
		{
			name:             "no user",
			httpWriter:       newLambdaResponseWriter(),
			httpReq:          http.Request{},
			wantBodyContains: []string{`"error":"unable to get user from request context"`},
		},
		{
			name:             "has a user but no credentials",
			httpWriter:       newLambdaResponseWriter(),
			httpReq:          reqWithUserNoCredentials,
			wantBodyContains: []string{`"error":"Found no credentials for user"`},
		},
		{
			name:       "has a user with credentials",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    reqWithUserCredentials,
			wantBodyContains: []string{
				`"rpId":"111.11.11.11"`,
				`{"publicKey":{"challenge":`,
				`"id":"` + string(userIDEncoded),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BeginLogin(tt.httpWriter, &tt.httpReq)

			gotBody := string(tt.httpWriter.Body)
			for _, w := range tt.wantBodyContains {
				assert.Contains(gotBody, w)
			}
		})
	}
}
