package mfa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

// These come from https://github.com/duo-labs/webauthn/blob/23776d77aa561cf1d5cf9f10a65daab336a1d399/protocol/assertion_test.go
const (
	testAssertID                = "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng"
	testAssertAuthenticatorData = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ"
	testAssertSignature         = "MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc"
	testAssertClientDataJSON    = "eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
	testAttestObject            = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw"
	testCredID                  = "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g"
	testChallenge               = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"
	testRpId                    = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA"
)

const testAssertionResponse = `{
	"id":"` + testCredID + `",
	"rawId":"` + testCredID + `",
	"type":"public-key",
	"response":{
		"authenticatorData":"` + testAssertAuthenticatorData + `",
		"signature":"` + testAssertSignature + `",
		"clientDataJSON":"` + testAssertClientDataJSON + `",
		"userHandle":"0ToAAAAAAAAAAA",
		"attestationObject":"` + testAttestObject + `"
		}
	}`

func getTestAssertionResponse(credID, authData, clientData, attestationObject string) []byte {
	return []byte(`{
	"id":"` + credID + `",
	"rawId":"` + credID + `",
	"type":"public-key",
	"response":{
		"authenticatorData":"` + authData + `",
		"clientDataJSON":"` + clientData + `",
		"attestationObject":"` + attestationObject + `"
		}
	}`)
}

func getTestAssertionRequest(credID1, authData1, clientData1, attestObject1 string, user *DynamoUser) *http.Request {

	assertResp := getTestAssertionResponse(credID1, authData1, clientData1, attestObject1)

	body := ioutil.NopCloser(bytes.NewReader(assertResp))

	reqWithBody := &http.Request{Body: body}
	ctxWithUser := context.WithValue(reqWithBody.Context(), UserContextKey, user)
	reqWithBody = reqWithBody.WithContext(ctxWithUser)
	return reqWithBody
}

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

func testAwsConfig() aws.Config {
	return aws.Config{
		Endpoint:   aws.String(os.Getenv("AWS_ENDPOINT")),
		Region:     aws.String(os.Getenv("AWS_DEFAULT_REGION")),
		DisableSSL: aws.Bool(true),
	}
}

func testEnvConfig(awsConfig aws.Config) EnvConfig {
	envCfg := EnvConfig{
		ApiKeyTable:      "api_keys",
		WebauthnTable:    "WebAuthn",
		AwsEndpoint:      os.Getenv("AWS_ENDPOINT"),
		AwsDefaultRegion: os.Getenv("AWS_DEFAULT_REGION"),
		AwsDisableSSL:    true,
		AWSConfig:        &awsConfig,
	}

	SetConfig(envCfg)
	return envCfg
}

func formatDynamoResults(results interface{}) string {
	resultsStr := fmt.Sprintf("%+v", results)
	resultsStr = strings.Replace(resultsStr, "  ", "", -1)
	resultsStr = strings.Replace(resultsStr, "\n", "", -1)

	return resultsStr
}

func Test_BeginRegistration(t *testing.T) {
	assert := require.New(t)

	// Needed for the envCfg and the storage
	awsConfig := testAwsConfig()

	// Needed for storage
	envCfg := testEnvConfig(awsConfig)

	localStorage, err := NewStorage(&awsConfig)
	assert.NoError(err, "failed creating local storage for test")

	err = initDb(nil)
	if err != nil {
		t.Error(err)
		return
	}

	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  localStorage,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",   // Display Name for your site
		RPID:          "111.11.11.11", // Generally the FQDN for your site
		Debug:         true,
	})

	assert.NoError(err, "failed creating new webAuthnClient for test")

	userID := "12345678-1234-1234-1234-123456789012"
	userIDEncoded := base64.StdEncoding.EncodeToString([]byte(userID))

	userNoID := DynamoUser{
		Name:           "Nelly_NoID",
		DisplayName:    "Nelly NoID",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		APIKeyValue:    apiKey.Key,
	}

	reqNoID := http.Request{}
	ctxNoID := context.WithValue(reqNoID.Context(), UserContextKey, &userNoID)
	reqNoID = *reqNoID.WithContext(ctxNoID)

	testUser := DynamoUser{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		APIKeyValue:    apiKey.Key,
	}

	reqWithUserID := http.Request{}
	ctxWithUserID := context.WithValue(reqWithUserID.Context(), UserContextKey, &testUser)
	reqWithUserID = *reqWithUserID.WithContext(ctxWithUserID)

	localStorage.Store(envConfig.WebauthnTable, ctxWithUserID)

	tests := []struct {
		name               string
		httpWriter         *lambdaResponseWriter
		httpReq            http.Request
		wantBodyContains   []string
		wantDynamoContains []string //  test will replace line ends and double spaces with blank string
	}{
		{
			name:       "no user",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    http.Request{},
			wantBodyContains: []string{
				`"error":"unable to get user from request context"`,
				`missing WebAuthClient in BeginRegistration`,
			},
		},
		{
			name:       "user has no id",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    reqNoID,
			wantBodyContains: []string{
				`"uuid":"`,
				`"id":"111.11.11.11"`,
				`"name":"TestRPName"`,
				`"publicKey":{`,
			},
			wantDynamoContains: []string{
				`{Count: 1`,
				`EncryptedSessionData: {B: <binary> len 158}`,
				`apiKey: {S: "` + apiKeyKey,
			},
		},
		{
			name:       "user has an id",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    reqWithUserID,
			wantBodyContains: []string{
				`"uuid":"` + userID,
				`"id":"111.11.11.11"`,
				`"name":"TestRPName"`,
				`"publicKey":{`,
				`"id":"` + string(userIDEncoded),
			},
			wantDynamoContains: []string{
				`{Count: 2`,
				`uuid: {S: "` + userID,
				`EncryptedSessionData: {B: <binary> len 158}`,
				`apiKey: {S: "` + apiKeyKey,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BeginRegistration(tt.httpWriter, &tt.httpReq)

			gotBody := string(tt.httpWriter.Body)
			for _, w := range tt.wantBodyContains {
				assert.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			params := &dynamodb.ScanInput{
				TableName: aws.String(envCfg.WebauthnTable),
			}

			results, err := localStorage.client.Scan(params)
			assert.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				assert.Contains(resultsStr, w)
			}
		})
	}
}

func Test_FinishRegistration(t *testing.T) {
	assert := require.New(t)

	awsConfig := testAwsConfig()
	envCfg := testEnvConfig(awsConfig)

	localStorage, err := NewStorage(&awsConfig)
	assert.NoError(err, "failed creating local storage for test")

	err = initDb(nil)
	if err != nil {
		t.Error(err)
		return
	}

	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  localStorage,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",       // Display Name for your site
		RPID:          "http://localhost", // Generally the FQDN for your site
		RPOrigin:      "http://localhost",
		Debug:         true,
	})

	assert.NoError(err, "failed creating new webAuthnClient for test")

	testUser := DynamoUser{
		ID:             testCredID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		APIKeyValue:    apiKey.Key,
		SessionData: webauthn.SessionData{
			UserID:    []byte(testCredID),
			Challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
		},
	}

	reqNoBody := http.Request{}
	ctxNoBody := context.WithValue(reqNoBody.Context(), UserContextKey, &testUser)
	reqNoBody = *reqNoBody.WithContext(ctxNoBody)

	// These are emulated Yubikey values
	const credID = "dmlydEtleTExLTA"
	const authData1 = `pAECAyYhWCC3zmSWHUv1deXdkfMP1wsgEQInu7up1xio6_t0TM3ZliJYIJdM6BaMYSl9WHEvxsFsI1EeUAT3jbbpbzJNJXKruCCE`
	const clientData = `eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVzhHekZVOHBHamhvUmJXckxEbGFtQWZxX3k0UzFDWkcxVnVvZVJMQVJyRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjaWRfcHVia2V5IjpudWxsfQ`
	const attestObject1 = `pGNmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAPjqxdYbYrUyAlBQR-nQ_tXX60AJBpgI0GQTQfL9ZseqAiBBQiDk9umctADNzsODWTHwIyajo5WCX0VbKwAyL3pcO2N4NWOBWQEnMIIBIzCByaADAgECAiEA9eyIyd78IXhUlVeZhjH5NGxU7M7pIYWn-BtckXLcusAwCgYIKoZIzj0EAwIwADAgFw0yMjAxMDEwMTAxMDFaGA8yMTIyMDEwMTAxMDEwMVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLfOZJYdS_V15d2R8w_XCyARAie7u6nXGKjr-3RMzdmWl0zoFoxhKX1YcS_GwWwjUR5QBPeNtulvMk0lcqu4IISjEjAQMA4GA1UdDwEB_wQEAwICpDAKBggqhkjOPQQDAgNJADBGAiEA8hwCpvxu1M99SiHyyVjRh5o1Q657O92FkF4SpA8u0lsCIQDR6hcx3bI4WMCZ5O1qW7xQheuTTRIc7VHPMzF_IikwtGhBdXRoRGF0YaVkcnBpZPZlZmxhZ3MAaGF0dF9kYXRho2ZhYWd1aWT2anB1YmxpY19rZXn2bWNyZWRlbnRpYWxfaWT2aGV4dF9kYXRh9mpzaWduX2NvdW50AGhhdXRoRGF0YViNhgW4ugjCDUL55FUVGHGJbQ4N6YBZYob7c20R7sAT4qRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAC3ZpcnRLZXkxMS0wpAECAyYhWCC3zmSWHUv1deXdkfMP1wsgEQInu7up1xio6_t0TM3ZliJYIJdM6BaMYSl9WHEvxsFsI1EeUAT3jbbpbzJNJXKruCCE`

	reqWithBody1 := getTestAssertionRequest(credID, authData1, clientData, attestObject1, &testUser)

	const authData2 = `pAECAyYhWCBWju412vLmFsmCyJUtOhbKLUYKX_sgwxT7jZduFiLLYCJYIHfMpmFqv_yNMRCYFkHf8ZaI_PxYUa6XyWbk5BTQ_LqF`
	const attestObject2 = `pGNmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAIO5erw2DrPaMEg_9M-LFlQjZuflevBexyUnRByP7CwZAiAH8Di8vF6pOuGiKaCjthHZ76B5faPnN_3pNHdBRZNpYGN4NWOBWQEmMIIBIjCByaADAgECAiEBIiQiGAIuTOJjXsDxVvxMJ1tAOLHMS6Wn-BtckXLcusAwCgYIKoZIzj0EAwIwADAgFw0yMjAxMDEwMTAxMDFaGA8yMTIyMDEwMTAxMDEwMVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFaO7jXa8uYWyYLIlS06FsotRgpf-yDDFPuNl24WIstgd8ymYWq__I0xEJgWQd_xloj8_FhRrpfJZuTkFND8uoWjEjAQMA4GA1UdDwEB_wQEAwICpDAKBggqhkjOPQQDAgNIADBFAiAhir4WEzviq4QRwxXUP8w8-JIdskomJXwdDIi3lJtGLgIhAMmtVF0Ld5TDb7ETDI6p5iuIvh6KBQguekyBtC6NVZKVaEF1dGhEYXRhpWRycGlk9mVmbGFncwBoYXR0X2RhdGGjZmFhZ3VpZPZqcHVibGljX2tlefZtY3JlZGVudGlhbF9pZPZoZXh0X2RhdGH2anNpZ25fY291bnQAaGF1dGhEYXRhWI2GBbi6CMINQvnkVRUYcYltDg3pgFlihvtzbRHuwBPipEEAAAAAAAAAAAAAAAAAAAAAAAAAAAALdmlydEtleTEzLTCkAQIDJiFYIFaO7jXa8uYWyYLIlS06FsotRgpf-yDDFPuNl24WIstgIlggd8ymYWq__I0xEJgWQd_xloj8_FhRrpfJZuTkFND8uoU`

	reqWithBody2 := getTestAssertionRequest(credID, authData2, clientData, attestObject2, &testUser)

	localStorage.Store(envConfig.WebauthnTable, &testUser)

	tests := []struct {
		name               string
		httpWriter         *lambdaResponseWriter
		httpReq            http.Request
		wantBodyContains   []string
		wantDynamoContains []string //  test will replace line ends and double spaces with blank string
		wantCredsCount     int
	}{
		{
			name:             "no user",
			httpWriter:       newLambdaResponseWriter(),
			httpReq:          http.Request{},
			wantBodyContains: []string{`"error":"unable to get user from request context"`},
		},
		{
			name:       "request has no body",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    reqNoBody,
			wantBodyContains: []string{
				`"error":"request Body may not be nil in FinishRegistration"`,
			},
		},
		{
			name:       "all good - first u2f key",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    *reqWithBody1,
			wantBodyContains: []string{
				`{"key_handle_hash":"g9MyqPUyL8trqvh0hQp8C3eeJfJascvinEbh6ImpVCc"}`,
			},
			wantDynamoContains: []string{
				`{Count: 1`,
				`uuid: {S: "` + testCredID,
				`EncryptedCredentials: {B: <binary>`,
				`apiKey: {S: "` + apiKeyKey,
			},
			wantCredsCount: 1,
		},
		{
			name:       "all good - second u2f key",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    *reqWithBody2,
			wantBodyContains: []string{
				`{"key_handle_hash":"tMRpoP2iSwo3rYH6lDT_kiPEltM3zFqyzaGfNayZ8SM"}`,
			},
			wantDynamoContains: []string{
				`{Count: 1`, // Still only one user, but now with 2 credentials
				`uuid: {S: "` + testCredID,
				`EncryptedCredentials: {B: <binary>`,
				`apiKey: {S: "` + apiKeyKey,
			},
			wantCredsCount: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			FinishRegistration(tt.httpWriter, &tt.httpReq)

			gotBody := string(tt.httpWriter.Body)
			for _, w := range tt.wantBodyContains {
				assert.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			params := &dynamodb.ScanInput{
				TableName: aws.String(envCfg.WebauthnTable),
			}

			results, err := localStorage.client.Scan(params)
			assert.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				assert.Contains(resultsStr, w)
			}
			if tt.wantCredsCount < 1 {
				return
			}

			// Ensure there are the correct number of credentials by first decoding them
			decoded, err := testUser.ApiKey.Decrypt(results.Items[0][`EncryptedCredentials`].B)
			assert.NoError(err, "error decrypting EncryptedCredentials")

			decoded = bytes.Trim(decoded, "\x00")
			var creds []webauthn.Credential
			err = json.Unmarshal(decoded, &creds)
			assert.NoError(err, "error unmarshalling user credential data")

			assert.Len(creds, tt.wantCredsCount, "incorrect number of user credentials")

		})
	}
}

func Test_BeginLogin(t *testing.T) {
	assert := require.New(t)

	// Needed for the envCfg and the storage
	awsConfig := testAwsConfig()

	// Needed for storage
	envCfg := testEnvConfig(awsConfig)

	localStorage, err := NewStorage(&awsConfig)
	assert.NoError(err, "failed creating local storage for test")

	err = initDb(nil)
	if err != nil {
		t.Error(err)
		return
	}

	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  localStorage,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",   // Display Name for your site
		RPID:          "111.11.11.11", // Generally the FQDN for your site
		Debug:         true,
	})

	assert.NoError(err, "failed creating new webAuthnClient for test")

	// Just check one of the error conditions with this user
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

	reqNoCredentials := http.Request{}
	ctxWithUser := context.WithValue(reqNoCredentials.Context(), UserContextKey, &userNoCreds)
	reqNoCredentials = *reqNoCredentials.WithContext(ctxWithUser)

	reqWithCredentials := http.Request{}
	ctxWithUserCredentials := context.WithValue(reqWithCredentials.Context(), UserContextKey, &userWithCreds)
	reqWithCredentials = *reqWithCredentials.WithContext(ctxWithUserCredentials)

	localStorage.Store(envConfig.WebauthnTable, ctxWithUserCredentials)

	tests := []struct {
		name               string
		httpWriter         *lambdaResponseWriter
		httpReq            http.Request
		wantBodyContains   []string
		wantDynamoContains []string //  test will replace line ends and double spaces with blank string
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
			httpReq:          reqNoCredentials,
			wantBodyContains: []string{`"error":"Found no credentials for user"`},
		},
		{
			name:       "has a user with credentials",
			httpWriter: newLambdaResponseWriter(),
			httpReq:    reqWithCredentials,
			wantBodyContains: []string{
				`"rpId":"111.11.11.11"`,
				`{"publicKey":{"challenge":`,
				`"id":"` + string(userIDEncoded),
			},
			wantDynamoContains: []string{
				`{Count: 1`,
				`uuid: {S: "` + userID,
				`EncryptedSessionData: {B: <binary> len 244}`,
				`apiKey: {S: "` + apiKeyKey,
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

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			params := &dynamodb.ScanInput{
				TableName: aws.String(envCfg.WebauthnTable),
			}

			results, err := localStorage.client.Scan(params)
			assert.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				assert.Contains(resultsStr, w)
			}
		})
	}
}
