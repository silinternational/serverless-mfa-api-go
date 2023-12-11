package actions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/silinternational/serverless-mfa-api-go/domain"
	"github.com/silinternational/serverless-mfa-api-go/models"
	"github.com/silinternational/serverless-mfa-api-go/u2fsimulator"
)

// These come from https://github.com/duo-labs/webauthn/blob/23776d77aa561cf1d5cf9f10a65daab336a1d399/protocol/assertion_test.go
// spellchecker: disable
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
	testRpOrigin      = "https://example.com"
)

// spellchecker: enable

func (as *ActionSuite) Test_webauthnBeginRegister() {
	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := models.ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  as.DB,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",   // Display Name for your site
		RPID:          "111.11.11.11", // Generally the FQDN for your site
		Debug:         true,
		RPOrigins:     []string{testRpOrigin},
	})

	as.NoError(err, "failed creating new webAuthnClient for test")

	const userID = "12345678-1234-1234-1234-123456789012"
	userIDEncoded := base64.StdEncoding.EncodeToString([]byte(userID))

	userNoID := models.User{
		Name:           "Nelly_NoID",
		DisplayName:    "Nelly NoID",
		Store:          as.DB,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
	}

	ctxNoID := context.WithValue(context.Background(), domain.UserContextKey, &userNoID)

	testUser := models.User{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          as.DB,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
	}

	ctxWithUserID := context.WithValue(context.Background(), domain.UserContextKey, &testUser)

	as.DB.Save(domain.Env.WebauthnTable, ctxWithUserID)

	tests := []struct {
		name               string
		context            context.Context
		wantBodyContains   []string
		wantDynamoContains []string //  test will replace line ends and double spaces with blank string
	}{
		{
			name:    "no user",
			context: context.Background(),
			wantBodyContains: []string{
				`"error":"unable to get user from request context"`,
				`missing WebAuthClient in BeginRegistration`,
			},
		},
		{
			name:    "user has no id",
			context: ctxNoID,
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
			name:    "user has an id",
			context: ctxWithUserID,
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
		as.T().Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(tt.context, http.MethodPost, "/webauthn"+pathRegister, nil)
			as.router.ServeHTTP(w, req)

			gotBody := w.Body.String()
			for _, w := range tt.wantBodyContains {
				as.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			results, err := as.DB.ScanTable(domain.Env.WebauthnTable)
			as.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := models.FormatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				as.Contains(resultsStr, w)
			}
		})
	}
}

func (as *ActionSuite) Test_webauthnFinishRegister() {
	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := models.ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  as.DB,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName", // Display Name for your site
		RPID:          localAppID,   // Generally the FQDN for your site
		RPOrigin:      testRpOrigin,
		Debug:         true,
	})

	as.NoError(err, "failed creating new webAuthnClient for test")

	const userID = "00345678-1234-1234-1234-123456789012"
	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE" // spellchecker: disable-line

	testUser := models.User{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          as.DB,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
		SessionData: webauthn.SessionData{
			UserID:    []byte(userID),
			Challenge: challenge,
		},
	}

	ctx := context.WithValue(context.Background(), domain.UserContextKey, &testUser)

	const credID = "dmlydEtleTExLTA" // spellchecker: disable-line
	clientDataStr, clientData := u2fsimulator.GetClientDataJson("webauthn.create", challenge, testRpOrigin)

	keyHandle1 := "virtualkey11" // spellchecker: disable-line
	keyHandle2 := "virtualkey12" // spellchecker: disable-line

	// These are emulated Yubikey values
	authData1, authDataBytes1, privateKey1 := u2fsimulator.GetAuthDataAndPrivateKey(localAppID, keyHandle1)
	attestObject1 := u2fsimulator.GetAttestationObject(authDataBytes1, clientData, keyHandle1, privateKey1, localAppID)
	body1 := getTestAssertionResponse(credID, authData1, clientDataStr, attestObject1)

	authData2, authDataBytes2, privateKey2 := u2fsimulator.GetAuthDataAndPrivateKey(localAppID, keyHandle2)
	attestObject2 := u2fsimulator.GetAttestationObject(authDataBytes2, clientData, keyHandle2, privateKey2, localAppID)
	body2 := getTestAssertionResponse(credID, authData2, clientDataStr, attestObject2)

	as.DB.Save(domain.Env.WebauthnTable, &testUser)

	tests := []struct {
		name               string
		context            context.Context
		body               io.Reader
		wantBodyContains   []string
		wantDynamoContains []string //  test will replace line ends and double spaces with blank string
		wantCredsCount     int
	}{
		{
			name:             "no user",
			context:          context.Background(),
			wantBodyContains: []string{`"error":"unable to get user from request context"`},
		},
		{
			name:    "request has no body",
			context: ctx,
			wantBodyContains: []string{
				`"error":"request Body may not be nil in FinishRegistration"`,
			},
		},
		{
			name:    "all good - first u2f key",
			context: ctx,
			body:    bytes.NewReader(body1),
			wantBodyContains: []string{
				`{"key_handle_hash":"ZYDzzEkj-JY80I7IviiMswRyYvTEh5DDXlhssMFs6Kw"}`, // spellchecker: disable-line
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
			context: ctx,
			body:    bytes.NewReader(body2),
			wantBodyContains: []string{
				`{"key_handle_hash":"ANyGhfjNgKwiap6UuhmYlZr_dao7x8SRFwU_IR7j2Pc"}`, // spellchecker: disable-line
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
		as.T().Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(tt.context, http.MethodPut, "/webauthn"+pathRegister, tt.body)
			as.router.ServeHTTP(w, req)

			gotBody := w.Body.String()
			for _, w := range tt.wantBodyContains {
				as.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			results, err := as.DB.ScanTable(domain.Env.WebauthnTable)
			as.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := models.FormatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				as.Contains(resultsStr, w)
			}
			if tt.wantCredsCount < 1 {
				return
			}

			// Ensure there are the correct number of credentials by first decoding them
			decoded, err := testUser.ApiKey.Decrypt(results.Items[0][`EncryptedCredentials`].B)
			as.NoError(err, "error decrypting EncryptedCredentials")

			decoded = bytes.Trim(decoded, "\x00")
			var creds []webauthn.Credential
			err = json.Unmarshal(decoded, &creds)
			as.NoError(err, "error unmarshalling user credential data")

			as.Len(creds, tt.wantCredsCount, "incorrect number of user credentials")
		})
	}
}

func (as *ActionSuite) Test_webauthnBeginLogin() {
	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := models.ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  as.DB,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",   // Display Name for your site
		RPID:          "111.11.11.11", // Generally the FQDN for your site
		Debug:         true,
		RPOrigins:     []string{testRpOrigin},
	})

	as.NoError(err, "failed creating new webAuthnClient for test")

	// Just check one of the error conditions with this user
	userNoCreds := models.User{
		ID:             "",
		Name:           "Nelly_NoCredentials",
		DisplayName:    "Nelly NoCredentials",
		Store:          as.DB,
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

	userWithCreds := models.User{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          as.DB,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
		Credentials:    creds,
	}

	ctxNoCreds := context.WithValue(context.Background(), domain.UserContextKey, &userNoCreds)
	ctxWithCreds := context.WithValue(context.Background(), domain.UserContextKey, &userWithCreds)

	as.DB.Save(domain.Env.WebauthnTable, ctxWithCreds)

	tests := []struct {
		name               string
		context            context.Context
		wantBodyContains   []string
		wantDynamoContains []string //  test will replace line ends and double spaces with blank string
	}{
		{
			name:             "no user",
			context:          context.Background(),
			wantBodyContains: []string{`"error":"unable to get user from request context"`},
		},
		{
			name:             "has a user but no credentials",
			context:          ctxNoCreds,
			wantBodyContains: []string{`"error":"Found no credentials for user"`},
		},
		{
			name:    "has a user with credentials",
			context: ctxWithCreds,
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
		as.T().Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(tt.context, http.MethodPost, "/webauthn"+pathLogin, nil)
			as.router.ServeHTTP(w, req)

			gotBody := w.Body.String()
			for _, w := range tt.wantBodyContains {
				as.Contains(gotBody, w)
			}

			if len(tt.wantDynamoContains) == 0 {
				return
			}

			results, err := as.DB.ScanTable(domain.Env.WebauthnTable)
			as.NoError(err, "failed to scan storage for results")

			// remove extra spaces and line endings
			resultsStr := models.FormatDynamoResults(results)

			for _, w := range tt.wantDynamoContains {
				as.Contains(resultsStr, w)
			}
		})
	}
}

func (as *ActionSuite) Test_webauthnFinishLogin() {
	apiKeyKey := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	apiKeySec := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))

	apiKey := models.ApiKey{
		Key:    apiKeyKey,
		Secret: apiKeySec,
		Store:  as.DB,
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName", // Display Name for your site
		RPID:          localAppID,   // Generally the FQDN for your site
		RPOrigin:      testRpOrigin,
		Debug:         true,
	})

	as.NoError(err, "failed creating new webAuthnClient for test")

	const userID = "00345678-1234-1234-1234-123456789012"
	userIDEncoded := base64.StdEncoding.EncodeToString([]byte(userID))

	// Give user two different credentials to see them come through
	const credID1 = "11345678-1234-1234-1234-123456789012"
	credIDEncoded1 := base64.StdEncoding.EncodeToString([]byte(credID1))
	khh1 := domain.HashAndEncode([]byte(credID1))

	const credID2 = "22345678-1234-1234-1234-123456789012"
	credIDEncoded2 := base64.StdEncoding.EncodeToString([]byte(credID2))
	khh2 := domain.HashAndEncode([]byte(credID2))

	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE" // spellchecker: disable-line

	keyHandle1 := "virtKey11" // spellchecker: disable-line
	authData1, authDataBytes1, privateKey1 := u2fsimulator.GetAuthDataAndPrivateKey(localAppID, keyHandle1)

	keyHandle2 := "virtKey12" // spellchecker: disable-line
	authData2, authDataBytes2, privateKey2 := u2fsimulator.GetAuthDataAndPrivateKey(localAppID, keyHandle2)

	clientData, cdBytes := u2fsimulator.GetClientDataJson("webauthn.get", challenge, testRpOrigin)
	publicKey1 := models.GetPublicKeyAsBytes(privateKey1)
	publicKey2 := models.GetPublicKeyAsBytes(privateKey2)

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

	userWithCreds := models.User{
		ID:             userID,
		Name:           "Charlie_HasCredentials",
		DisplayName:    "Charlie HasCredentials",
		Store:          as.DB,
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

	signature1 := models.GenerateAuthenticationSig(authDataBytes1, cdBytes, privateKey1)

	assertionResponse1 := `{
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

	body1 := bytes.NewReader([]byte(assertionResponse1))
	ctx1 := context.WithValue(context.Background(), domain.UserContextKey, &userWithCreds)

	as.DB.Save(domain.Env.WebauthnTable, ctx1)

	signature2 := models.GenerateAuthenticationSig(authDataBytes2, cdBytes, privateKey1)

	assertionResponse2 := `{
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

	body2 := bytes.NewReader([]byte(assertionResponse2))
	ctx2 := context.WithValue(context.Background(), domain.UserContextKey, &userWithCreds)

	as.DB.Save(domain.Env.WebauthnTable, ctx2)

	tests := []struct {
		name             string
		context          context.Context
		body             io.Reader
		wantBodyContains []string
	}{
		{
			name:             "no user",
			context:          context.Background(),
			wantBodyContains: []string{`"error":"unable to get user from request context"`},
		},
		{
			name:    "with first credential",
			context: ctx1,
			body:    body1,
			wantBodyContains: []string{
				`"credentialId":"` + credID1 + `"`,
				`"key_handle_hash":"` + khh1 + `"`,
			},
		},
		{
			name:    "with second credential",
			context: ctx2,
			body:    body2,
			wantBodyContains: []string{
				`"credentialId":"` + credID2 + `"`,
				`"key_handle_hash":"` + khh2 + `"`,
			},
		},
	}
	for _, tt := range tests {
		as.T().Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(tt.context, http.MethodPut, "/webauthn"+pathLogin, tt.body)
			as.router.ServeHTTP(w, req)

			gotBody := w.Body.String()
			for _, w := range tt.wantBodyContains {
				as.Contains(gotBody, w, "missing value in body")
			}
		})
	}
}

func (as *ActionSuite) Test_webauthnDeleteCredential() {
	users, err := models.GetTestWebauthnUsers(as.DB, as.webauthn)
	as.NoError(err, "did not initialize test users correctly")

	testUser0, testUser1, testUser2 := users[0], users[1], users[2]

	for i, u := range []models.User{testUser0, testUser1, testUser2} {
		as.NoError(u.ApiKey.Hash(), "error trying to hash apikey: %d", i)
		as.NoError(u.EncryptAndStoreCredentials(), "failed updating test user")
		as.NoError(u.ApiKey.Store.Save(domain.Env.ApiKeyTable, u.ApiKey), "failed saving initial apikey")
	}

	results, err := as.DB.ScanTable(domain.Env.ApiKeyTable)
	as.NoError(err, "failed to scan models.ApiKey storage for results")

	resultsStr := models.FormatDynamoResults(results)
	as.Contains(resultsStr, "Count: 3", "initial models.ApiKey data wasn't saved properly")

	results, err = as.DB.ScanTable(domain.Env.WebauthnTable)
	as.NoError(err, "failed to scan Webauthn storage for results")

	resultsStr = models.FormatDynamoResults(results)
	as.Contains(resultsStr, "Count: 3", "updated Webauthn data wasn't saved properly")

	tests := []struct {
		name            string
		user            models.User
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
			credID:     domain.LegacyU2FCredID,
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
			credID:         domain.HashAndEncode(testUser2.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			wantContains:   []string{testUser0.ID, testUser1.ID, testUser2.ID},
			wantCredIDs:    [][]byte{testUser2.Credentials[1].ID},
			dontWantCredID: testUser2.Credentials[0].ID,
		},
	}
	for _, tt := range tests {
		as.T().Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx := context.WithValue(context.Background(), domain.UserContextKey, &tt.user)
			request, _ := http.NewRequestWithContext(
				ctx,
				http.MethodDelete,
				fmt.Sprintf("/webauthn%s/%s", pathCredential, tt.credID),
				nil,
			)

			request.Header.Set("x-mfa-apikey", tt.user.ApiKeyValue)
			request.Header.Set("x-mfa-apisecret", tt.user.ApiKey.Secret)
			request.Header.Set("x-mfa-RPDisplayName", "TestRPName")
			request.Header.Set("x-mfa-RPID", "111.11.11.11")
			request.Header.Set("x-mfa-UserUUID", tt.user.ID)
			request.Header.Set("x-mfa-Username", tt.user.Name)
			request.Header.Set("x-mfa-UserDisplayName", tt.user.DisplayName)

			as.router.ServeHTTP(w, request)

			as.Equal(tt.wantStatus, w.Code, "incorrect http status")

			if tt.wantStatus != http.StatusNoContent {
				return
			}

			results, err := as.DB.ScanTable(domain.Env.WebauthnTable)
			as.NoError(err, "failed to scan storage for results")

			resultsStr := models.FormatDynamoResults(results)

			for _, w := range tt.wantContains {
				as.Contains(resultsStr, w, "incorrect db results missing string")
			}

			gotUser := tt.user
			gotUser.Load()

			as.Len(gotUser.Credentials, len(tt.wantCredIDs), "incorrect remaining credential ids")

			for i, w := range tt.wantCredIDs {
				as.Equal(string(w), string(gotUser.Credentials[i].ID), "incorrect credential id")
			}

			if len(tt.dontWantCredID) == 0 {
				return
			}

			for _, g := range gotUser.Credentials {
				as.NotEqual(string(tt.dontWantCredID), string(g.ID), "unexpected credential id")
			}
		})
	}
}

func (as *ActionSuite) Test_GetSignatureForLogin() {
	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE" // spellchecker: disable-line

	cd := models.ClientData{
		Typ:       "webauthn.get",
		Origin:    localAppID,
		Challenge: challenge,
	}

	clientData, err := json.Marshal(cd)
	as.NoError(err, "error marshalling client data")

	// TODO figure out if this was supposed to be used
	// xyStr := "4843956129390645175905258525279791420276294952604174799584408071708240463528636134250956749795798585127919587881956611106672985015071877198253568414405109"

	// bigXY, ok := new(big.Int).SetString(xyStr, 16)
	// if !ok {
	// 	panic("Failed making bigint")
	// }

	// xyData := []byte{4}
	// xyData = append(xyData, bigXY.Bytes()...)

	keyHandle := "virtKey11" // spellchecker: disable-line
	_, authDataBytes1, privateKey := u2fsimulator.GetAuthDataAndPrivateKey(localAppID, keyHandle)
	signature := models.GenerateAuthenticationSig(authDataBytes1, clientData, privateKey)

	want := "MEYCIQDH_BmLNjJNqS8b725jiqzyc5JZmNh8wYuaPBH3PjELMwIhANsuNznzM92SrYonfrX9-nL4CzOhuiOSxkZ7YFmOkTdd" // spellchecker: disable-line
	as.Equal(want, signature, "incorrect signature")
}

func (as *ActionSuite) Test_GetAuthDataAndPrivateKey() {
	keyHandle := "virtKey11" // spellchecker: disable-line
	authData, authDataBytes, privateKey := u2fsimulator.GetAuthDataAndPrivateKey(localAppID, keyHandle)

	want := `hgW4ugjCDUL55FUVGHGJbQ4N6YBZYob7c20R7sAT4qRBAAAAAAAAAAAAAAAAAAAAAAAAAAAACXZpcnRLZXkxMaQBAgMmIVggBtYaQhitMvmuvKeeUZmuh96TmXTRGxB_6bfslWmTVF4iWCCK1h-O_T8R6MjkIWCsX-Pry8RJhuOxbDwovnYJBu0SZw` // spellchecker: disable-line
	as.Equal(want, authData, "incorrect bare authentication data")

	as.Len(authDataBytes, 139, "incorrect length of authDataBytes")

	as.Equal("P-256", privateKey.Params().Name)
}

func (as *ActionSuite) Test_GetPublicKeyAsBytes() {
	const keyHandle = "virtKey11" // spellchecker: disable-line
	_, _, privateKey := u2fsimulator.GetAuthDataAndPrivateKey(localAppID, keyHandle)

	got := models.GetPublicKeyAsBytes(privateKey)

	want := []byte{4, 6, 214, 26, 66, 24, 173, 50, 249, 174, 188, 167, 158, 81, 153, 174, 135, 222, 147, 153, 116, 209, 27, 16, 127, 233, 183, 236, 149, 105, 147, 84, 94, 138, 214, 31, 142, 253, 63, 17, 232, 200, 228, 33, 96, 172, 95, 227, 235, 203, 196, 73, 134, 227, 177, 108, 60, 40, 190, 118, 9, 6, 237, 18, 103}

	as.Equal(want, got, "incorrect public Key")
}

func (as *ActionSuite) Test_Parse() {
	id := "kCvEeC0h5T4cmnggaesuj2rpiOloBbtRMuGhBUEHmAOHDTPW9pf5ZkXZtm8OQ7HSYT6XnL0W21rrLvWaVGSzag=="
	body := `{"rawId":"` + id +
		`","response":{"attestationObject":"` + testAttestObject +
		`","getTransports":{},"clientDataJSON":"` + testAssertClientDataJSON +
		`"},"getClientExtensionResults":{},"id":"` + id +
		`","type":"public-key"}`

	newReader := domain.FixEncoding([]byte(body))

	resp, err := protocol.ParseCredentialCreationResponseBody(newReader)
	as.NoError(err)

	want := strings.ReplaceAll(id, "=", "")
	as.Equal(want, resp.ID, "incorrect RawID")
}

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
