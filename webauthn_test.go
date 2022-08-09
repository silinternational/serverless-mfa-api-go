package mfa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
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

	AssertionTypeFido = "fido-u2f"
)

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
	assert := require.New(t)
	id := "kCvEeC0h5T4cmnggaesuj2rpiOloBbtRMuGhBUEHmAOHDTPW9pf5ZkXZtm8OQ7HSYT6XnL0W21rrLvWaVGSzag=="
	body := `{"rawId":"` + id +
		`","response":{"attestationObject":"` + testAttestObject +
		`","getTransports":{},"clientDataJSON":"` + testAssertClientDataJSON +
		`"},"getClientExtensionResults":{},"id":"` + id +
		`","type":"public-key"}`

	newReader := fixEncoding([]byte(body))

	pccr, err := protocol.ParseCredentialCreationResponseBody(newReader)
	assert.NoError(err)

	want := strings.ReplaceAll(id, "=", "")
	assert.Equal(want, pccr.ID, "incorrect RawID")
}

func formatDynamoResults(results interface{}) string {
	resultsStr := fmt.Sprintf("%+v", results)
	resultsStr = strings.Replace(resultsStr, "  ", "", -1)
	resultsStr = strings.Replace(resultsStr, "\n", "", -1)

	return resultsStr
}

func (ms *MfaSuite) Test_BeginRegistration() {
	awsConfig := testAwsConfig()
	envCfg := testEnvConfig(awsConfig)
	localStorage, err := NewStorage(&awsConfig)
	ms.NoError(err, "failed creating local storage for test")

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

	ms.NoError(err, "failed creating new webAuthnClient for test")

	const userID = "12345678-1234-1234-1234-123456789012"
	userIDEncoded := base64.StdEncoding.EncodeToString([]byte(userID))

	userNoID := DynamoUser{
		Name:           "Nelly_NoID",
		DisplayName:    "Nelly NoID",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
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
		ApiKeyValue:    apiKey.Key,
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
				`EncryptedSessionData: {B: <binary> len`,
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
				`EncryptedSessionData: {B: <binary> len`,
				`apiKey: {S: "` + apiKeyKey,
			},
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {
			BeginRegistration(tt.httpWriter, &tt.httpReq)

			gotBody := string(tt.httpWriter.Body)
			for _, w := range tt.wantBodyContains {
				ms.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			params := &dynamodb.ScanInput{
				TableName: aws.String(envCfg.WebauthnTable),
			}

			results, err := localStorage.client.Scan(params)
			ms.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				ms.Contains(resultsStr, w)
			}
		})
	}
}

func (ms *MfaSuite) Test_FinishRegistration() {
	awsConfig := testAwsConfig()
	envCfg := testEnvConfig(awsConfig)
	localStorage, err := NewStorage(&awsConfig)
	ms.NoError(err, "failed creating local storage for test")

	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  localStorage,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName", // Display Name for your site
		RPID:          localAppID,   // Generally the FQDN for your site
		RPOrigin:      localAppID,
		Debug:         true,
	})

	ms.NoError(err, "failed creating new webAuthnClient for test")

	const userID = "00345678-1234-1234-1234-123456789012"
	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"

	testUser := DynamoUser{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
		SessionData: webauthn.SessionData{
			UserID:    []byte(userID),
			Challenge: challenge,
		},
	}

	reqNoBody := http.Request{}
	ctxNoBody := context.WithValue(reqNoBody.Context(), UserContextKey, &testUser)
	reqNoBody = *reqNoBody.WithContext(ctxNoBody)

	const credID = "dmlydEtleTExLTA"
	clientDataStr, clientData := getClientDataJson("webauthn.create", challenge)

	keyHandle1 := "virtualkey11"
	keyHandle2 := "virtualkey12"

	// These are emulated Yubikey values
	authData1, authDataBytes1, privateKey1 := GetAuthDataAndPrivateKey(localAppID, keyHandle1)
	attestObject1 := GetAttestationObject(authDataBytes1, clientData, keyHandle1, privateKey1)
	reqWithBody1 := getTestAssertionRequest(credID, authData1, clientDataStr, attestObject1, &testUser)

	authData2, authDataBytes2, privateKey2 := GetAuthDataAndPrivateKey(localAppID, "virtualkey12")
	attestObject2 := GetAttestationObject(authDataBytes2, clientData, keyHandle2, privateKey2)
	reqWithBody2 := getTestAssertionRequest(credID, authData2, clientDataStr, attestObject2, &testUser)

	localStorage.Store(envConfig.WebauthnTable, &testUser)

	tests := []struct {
		name               string
		httpReq            http.Request
		wantBodyContains   []string
		wantDynamoContains []string //  test will replace line ends and double spaces with blank string
		wantCredsCount     int
	}{
		{
			name:             "no user",
			httpReq:          http.Request{},
			wantBodyContains: []string{`"error":"unable to get user from request context"`},
		},
		{
			name:    "request has no body",
			httpReq: reqNoBody,
			wantBodyContains: []string{
				`"error":"request Body may not be nil in FinishRegistration"`,
			},
		},
		{
			name:    "all good - first u2f key",
			httpReq: *reqWithBody1,
			wantBodyContains: []string{
				`{"key_handle_hash":"ZYDzzEkj-JY80I7IviiMswRyYvTEh5DDXlhssMFs6Kw"}`,
			},
			wantDynamoContains: []string{
				`{Count: 1`,
				`uuid: {S: "` + userID,
				`EncryptedCredentials: {B: <binary>`,
				`apiKey: {S: "` + apiKeyKey,
			},
			wantCredsCount: 1,
		},
		{
			name:    "all good - second u2f key",
			httpReq: *reqWithBody2,
			wantBodyContains: []string{
				`{"key_handle_hash":"ANyGhfjNgKwiap6UuhmYlZr_dao7x8SRFwU_IR7j2Pc"}`,
			},
			wantDynamoContains: []string{
				`{Count: 1`, // Still only one user, but now with 2 credentials
				`uuid: {S: "` + userID,
				`EncryptedCredentials: {B: <binary>`,
				`apiKey: {S: "` + apiKeyKey,
			},
			wantCredsCount: 2,
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {
			httpWriter := newLambdaResponseWriter()
			FinishRegistration(httpWriter, &tt.httpReq)

			gotBody := string(httpWriter.Body)
			for _, w := range tt.wantBodyContains {
				ms.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			params := &dynamodb.ScanInput{
				TableName: aws.String(envCfg.WebauthnTable),
			}

			results, err := localStorage.client.Scan(params)
			ms.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				ms.Contains(resultsStr, w)
			}
			if tt.wantCredsCount < 1 {
				return
			}

			// Ensure there are the correct number of credentials by first decoding them
			decoded, err := testUser.ApiKey.Decrypt(results.Items[0][`EncryptedCredentials`].B)
			ms.NoError(err, "error decrypting EncryptedCredentials")

			decoded = bytes.Trim(decoded, "\x00")
			var creds []webauthn.Credential
			err = json.Unmarshal(decoded, &creds)
			ms.NoError(err, "error unmarshalling user credential data")

			ms.Len(creds, tt.wantCredsCount, "incorrect number of user credentials")
		})
	}
}

func (ms *MfaSuite) Test_BeginLogin() {
	awsConfig := testAwsConfig()
	envCfg := testEnvConfig(awsConfig)
	localStorage, err := NewStorage(&awsConfig)
	ms.NoError(err, "failed creating local storage for test")

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

	ms.NoError(err, "failed creating new webAuthnClient for test")

	// Just check one of the error conditions with this user
	userNoCreds := DynamoUser{
		ID:             "",
		Name:           "Nelly_NoCredentials",
		DisplayName:    "Nelly NoCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
	}

	const userID = "00345678-1234-1234-1234-123456789012"

	// Give user two different credentials to see them come through
	const credID1 = "11345678-1234-1234-1234-123456789012"
	credIDEncoded1 := base64.StdEncoding.EncodeToString([]byte(credID1))

	const credID2 = "22345678-1234-1234-1234-123456789012"
	credIDEncoded2 := base64.StdEncoding.EncodeToString([]byte(credID2))

	creds := []webauthn.Credential{
		{
			ID:        []byte(credID1),
			PublicKey: []byte("1234"),
		},
		{
			ID:        []byte(credID2),
			PublicKey: []byte("5678"),
		},
	}

	userWithCreds := DynamoUser{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
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
				`"allowCredentials":[{"type":"public-key","id":"`,
				`"id":"` + string(credIDEncoded1),
				`"id":"` + string(credIDEncoded2),
			},
			wantDynamoContains: []string{
				`{Count: 1`,
				`uuid: {S: "` + userID,
				`EncryptedSessionData: {B: <binary> len `,
				`apiKey: {S: "` + apiKeyKey,
			},
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {
			BeginLogin(tt.httpWriter, &tt.httpReq)

			gotBody := string(tt.httpWriter.Body)
			for _, w := range tt.wantBodyContains {
				ms.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			params := &dynamodb.ScanInput{
				TableName: aws.String(envCfg.WebauthnTable),
			}

			results, err := localStorage.client.Scan(params)
			ms.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				ms.Contains(resultsStr, w)
			}
		})
	}
}

func (ms *MfaSuite) Test_FinishLogin() {
	awsConfig := testAwsConfig()
	localStorage, err := NewStorage(&awsConfig)
	ms.NoError(err, "failed creating local storage for test")

	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  localStorage,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName", // Display Name for your site
		RPID:          localAppID,   // Generally the FQDN for your site
		Debug:         true,
	})

	ms.NoError(err, "failed creating new webAuthnClient for test")

	const userID = "00345678-1234-1234-1234-123456789012"
	userIDEncoded := base64.StdEncoding.EncodeToString([]byte(userID))

	// Give user two different credentials to see them come through
	const credID1 = "11345678-1234-1234-1234-123456789012"
	credIDEncoded1 := base64.StdEncoding.EncodeToString([]byte(credID1))

	const credID2 = "22345678-1234-1234-1234-123456789012"
	credIDEncoded2 := base64.StdEncoding.EncodeToString([]byte(credID2))

	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"

	keyHandle1 := "virtKey11"
	authData1, authDataBytes1, privateKey1 := GetAuthDataAndPrivateKey(localAppID, keyHandle1)

	keyHandle2 := "virtKey12"
	authData2, authDataBytes2, privateKey2 := GetAuthDataAndPrivateKey(localAppID, keyHandle2)

	clientData, cdBytes := getClientDataJson("webauthn.get", challenge)
	publicKey1 := GetPublicKeyAsBytes(privateKey1)
	publicKey2 := GetPublicKeyAsBytes(privateKey2)

	creds := []webauthn.Credential{
		{
			ID:              []byte(credID1),
			PublicKey:       publicKey1,
			AttestationType: AssertionTypeFido,
		},
		{
			ID:              []byte(credID2),
			PublicKey:       publicKey2,
			AttestationType: AssertionTypeFido,
		},
	}

	userWithCreds := DynamoUser{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
		SessionData: webauthn.SessionData{
			UserID:     []byte(userID),
			Challenge:  challenge,
			Extensions: protocol.AuthenticationExtensions{"appid": localAppID},
		},
		Credentials: creds,
	}

	signature1 := GenerateAuthenticationSig(authDataBytes1, cdBytes, privateKey1)

	var assertionResponse1 = `{
		  "id":"` + credIDEncoded1 + `",
		  "rawId":"` + credIDEncoded1 + `",
		  "type":"public-key",
		  "clientExtensionResults":{"appid":true},
		  "response":{
		    "authenticatorData":"` + authData1 + `",
			"clientDataJSON":"` + clientData + `",
			"signature":"` + signature1 + `",
			"userHandle":"` + userIDEncoded + `"
          }
		}`

	body1 := ioutil.NopCloser(bytes.NewReader([]byte(assertionResponse1)))
	reqWithBody1 := http.Request{Body: body1}
	ctxUserCred1 := context.WithValue(reqWithBody1.Context(), UserContextKey, &userWithCreds)
	reqWithBody1 = *reqWithBody1.WithContext(ctxUserCred1)

	localStorage.Store(envConfig.WebauthnTable, ctxUserCred1)

	signature2 := GenerateAuthenticationSig(authDataBytes2, cdBytes, privateKey1)

	var assertionResponse2 = `{
		  "id":"` + credIDEncoded2 + `",
		  "rawId":"` + credIDEncoded2 + `",
		  "type":"public-key",
		  "clientExtensionResults":{"appid":true},
		  "response":{
		    "authenticatorData":"` + authData2 + `",
			"clientDataJSON":"` + clientData + `",
			"signature":"` + signature2 + `",
			"userHandle":"` + userIDEncoded + `"
          }
		}`

	body2 := ioutil.NopCloser(bytes.NewReader([]byte(assertionResponse2)))

	reqWithBody2 := http.Request{Body: body2}
	ctxUserCred2 := context.WithValue(reqWithBody2.Context(), UserContextKey, &userWithCreds)
	reqWithBody2 = *reqWithBody2.WithContext(ctxUserCred2)

	localStorage.Store(envConfig.WebauthnTable, ctxUserCred2)

	tests := []struct {
		name             string
		httpReq          http.Request
		wantBodyContains []string
	}{
		{
			name:             "no user",
			httpReq:          http.Request{},
			wantBodyContains: []string{`"error":"unable to get user from request context"`},
		},
		{
			name:    "with first credential",
			httpReq: reqWithBody1,
			wantBodyContains: []string{
				`"credentialId":"` + credID1 + `"`,
			},
		},
		{
			name:    "with second credential",
			httpReq: reqWithBody2,
			wantBodyContains: []string{
				`"credentialId":"` + credID2 + `"`,
			},
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {
			httpWriter := newLambdaResponseWriter()
			FinishLogin(httpWriter, &tt.httpReq)

			gotBody := string(httpWriter.Body)

			for _, w := range tt.wantBodyContains {
				ms.Contains(gotBody, w, "missing value in body")
			}
		})
	}
}

func Test_GetSignatureForLogin(t *testing.T) {
	assert := require.New(t)

	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"

	cd := ClientData{
		Typ:       "webauthn.get",
		Origin:    localAppID,
		Challenge: challenge,
	}

	clientData, err := json.Marshal(cd)
	if err != nil {
		panic("error marshalling client data: " + err.Error())
	}

	xyStr := "4843956129390645175905258525279791420276294952604174799584408071708240463528636134250956749795798585127919587881956611106672985015071877198253568414405109"

	bigXY, ok := new(big.Int).SetString(xyStr, 16)
	if !ok {
		panic("Failed making bigint")
	}

	xyData := []byte{4}
	xyData = append(xyData, bigXY.Bytes()...)

	keyHandle := "virtKey11"
	_, authDataBytes1, privateKey := GetAuthDataAndPrivateKey(localAppID, keyHandle)
	signature := GenerateAuthenticationSig(authDataBytes1, clientData, privateKey)

	want := "MEYCIQDH_BmLNjJNqS8b725jiqzyc5JZmNh8wYuaPBH3PjELMwIhANsuNznzM92SrYonfrX9-nL4CzOhuiOSxkZ7YFmOkTdd"
	assert.Equal(want, signature, "incorrect signature")
}

func Test_GetAuthDataAndPrivateKey(t *testing.T) {
	assert := require.New(t)
	keyHandle := "virtKey11"
	authData, authDataBytes, privateKey := GetAuthDataAndPrivateKey(localAppID, keyHandle)

	want := `hgW4ugjCDUL55FUVGHGJbQ4N6YBZYob7c20R7sAT4qRBAAAAAAAAAAAAAAAAAAAAAAAAAAAACXZpcnRLZXkxMaQBAgMmIVggBtYaQhitMvmuvKeeUZmuh96TmXTRGxB_6bfslWmTVF4iWCCK1h-O_T8R6MjkIWCsX-Pry8RJhuOxbDwovnYJBu0SZw`
	assert.Equal(want, authData, "incorrect bare authentication data")

	assert.Len(authDataBytes, 139, "incorrect length of authDataBytes")

	assert.Equal("P-256", privateKey.Params().Name)
}

func Test_GetPublicKeyAsBytes(t *testing.T) {
	assert := require.New(t)
	const keyHandle = "virtKey11"
	_, _, privateKey := GetAuthDataAndPrivateKey(localAppID, keyHandle)

	got := GetPublicKeyAsBytes(privateKey)

	want := []byte{4, 6, 214, 26, 66, 24, 173, 50, 249, 174, 188, 167, 158, 81, 153, 174, 135, 222, 147, 153, 116, 209, 27, 16, 127, 233, 183, 236, 149, 105, 147, 84, 94, 138, 214, 31, 142, 253, 63, 17, 232, 200, 228, 33, 96, 172, 95, 227, 235, 203, 196, 73, 134, 227, 177, 108, 60, 40, 190, 118, 9, 6, 237, 18, 103}

	assert.Equal(want, got, "incorrect public Key")

}

func Router() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc(fmt.Sprintf("/webauthn/credential/{%s}", IDParam), DeleteCredential).Methods("DELETE")
	// Ensure a request without an id gets handled properly
	router.HandleFunc("/webauthn/credential/", DeleteCredential).Methods("DELETE")
	router.HandleFunc("/webauthn/credential", DeleteCredential).Methods("DELETE")

	// authenticate request based on api key and secret in headers
	// also adds user to context
	router.Use(testAuthnMiddleware)

	return router
}

func testAuthnMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := AuthenticateRequest(r)
		if err != nil {
			http.Error(w, fmt.Sprintf("unable to authenticate request: %s", err), http.StatusUnauthorized)
			return
		}

		// Add user into context for further use
		ctx := context.WithValue(r.Context(), UserContextKey, user)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (ms *MfaSuite) Test_DeleteCredential() {

	baseConfigs := getDBConfig(ms)

	users := getTestWebauthnUsers(ms, baseConfigs)
	testUser0, testUser1, testUser2 := users[0], users[1], users[2]

	for i, u := range []DynamoUser{testUser0, testUser1, testUser2} {
		ms.NoError(u.ApiKey.Hash(), "error trying to hash apikey: %d", i)
		ms.NoError(u.encryptAndStoreCredentials(), "failed updating test user")
		ms.NoError(u.ApiKey.Store.Store(baseConfigs.EnvConfig.ApiKeyTable, u.ApiKey), "failed saving initial apikey")
	}

	params := &dynamodb.ScanInput{
		TableName: aws.String(baseConfigs.EnvConfig.ApiKeyTable),
	}

	results, err := baseConfigs.Storage.client.Scan(params)
	ms.NoError(err, "failed to scan ApiKey storage for results")

	resultsStr := formatDynamoResults(results)
	ms.Contains(resultsStr, "Count: 3", "initial ApiKey data wasn't saved properly")

	params.TableName = aws.String(baseConfigs.EnvConfig.WebauthnTable)

	results, err = baseConfigs.Storage.client.Scan(params)
	ms.NoError(err, "failed to scan Webauthn storage for results")

	resultsStr = formatDynamoResults(results)
	ms.Contains(resultsStr, "Count: 3", "updated Webauthn data wasn't saved properly")

	tests := []struct {
		name            string
		user            DynamoUser
		credID          string
		wantErrContains string
		wantStatus      int
		wantContains    []string
		wantCredIDs     [][]byte
		dontWantCredID  []byte
	}{
		{
			name:       "legacy u2f credential",
			user:       testUser0,
			credID:     LegacyU2FCredID,
			wantStatus: http.StatusNoContent,
		},
		{
			name:            "noID",
			user:            testUser1,
			credID:          "",
			wantErrContains: "credential not found with blank id",
			wantStatus:      http.StatusBadRequest,
		},
		{
			name:            "one credential but bad credential ID",
			user:            testUser1,
			credID:          "bad_one",
			wantErrContains: "credential not found with id: bad_one",
			wantStatus:      http.StatusNotFound,
			wantContains:    []string{testUser1.ID},
			wantCredIDs:     [][]byte{testUser1.Credentials[0].ID},
		},
		{
			name:           "two credentials and one is deleted",
			user:           testUser2,
			credID:         hashAndEncodeKeyHandle(testUser2.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			wantContains:   []string{testUser0.ID, testUser1.ID, testUser2.ID},
			wantCredIDs:    [][]byte{testUser2.Credentials[1].ID},
			dontWantCredID: testUser2.Credentials[0].ID,
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {

			request, _ := http.NewRequest("DELETE", fmt.Sprintf("/webauthn/credential/%s", tt.credID), nil)

			request.Header.Set("x-mfa-apikey", tt.user.ApiKeyValue)
			request.Header.Set("x-mfa-apisecret", tt.user.ApiKey.Secret)
			request.Header.Set("x-mfa-RPDisplayName", "TestRPName")
			request.Header.Set("x-mfa-RPID", "111.11.11.11")
			request.Header.Set("x-mfa-UserUUID", tt.user.ID)
			request.Header.Set("x-mfa-Username", tt.user.Name)
			request.Header.Set("x-mfa-UserDisplayName", tt.user.DisplayName)

			ctxWithUser := context.WithValue(request.Context(), UserContextKey, &tt.user)
			request = request.WithContext(ctxWithUser)
			baseConfigs.Storage.Store(baseConfigs.EnvConfig.WebauthnTable, ctxWithUser)

			response := httptest.NewRecorder()
			Router().ServeHTTP(response, request)
			ms.Equal(tt.wantStatus, response.Code, "incorrect http status")

			if tt.wantStatus != http.StatusNoContent {
				return
			}

			results, err := baseConfigs.Storage.client.Scan(params)
			ms.NoError(err, "failed to scan storage for results")

			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantContains {
				ms.Contains(resultsStr, w, "incorrect db results missing string")
			}

			gotUser := tt.user
			gotUser.Load()

			ms.Len(gotUser.Credentials, len(tt.wantCredIDs), "incorrect remaining credential ids")

			for i, w := range tt.wantCredIDs {
				ms.Equal(string(w), string(gotUser.Credentials[i].ID), "incorrect credential id")
			}

			if len(tt.dontWantCredID) == 0 {
				return
			}

			for _, g := range gotUser.Credentials {
				ms.NotEqual(string(tt.dontWantCredID), string(g.ID), "unexpected credential id")
			}
		})
	}
}
