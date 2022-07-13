package mfa

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/duo-labs/webauthn/webauthn"
)

func (ms *MfaSuite) Test_User_DeleteCredential() {

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

	const userID = "10345678-1234-1234-1234-123456789012"
	cred11 := webauthn.Credential{ID: []byte("C11")}
	cred21 := webauthn.Credential{ID: []byte("C21")}
	cred22 := webauthn.Credential{ID: []byte("C22")}

	testUser0 := DynamoUser{
		ID:             "10345678-1234-1234-1234-123456789012",
		Name:           "Nancy_NoCredential",
		Store:          localStorage,
		WebAuthnClient: web,
		ApiKey:         apiKey,
		ApiKeyValue:    apiKey.Key,
		Credentials:    []webauthn.Credential{},
	}

	testUser1 := testUser0
	testUser1.ID = "11345678-1234-1234-1234-123456789012"
	testUser1.Name = "Oscar_OneCredential"
	testUser1.Credentials = []webauthn.Credential{cred11}

	testUser2 := testUser0
	testUser2.ID = "12345678-1234-1234-1234-123456789012"
	testUser2.Name = "Tony_TwoCredentials"
	testUser2.Credentials = []webauthn.Credential{cred21, cred22}

	for _, u := range []DynamoUser{testUser0, testUser1, testUser2} {
		ms.NoError(u.encryptAndStoreCredentials(), "failed saving initial test user")
	}

	params := &dynamodb.ScanInput{
		TableName: aws.String(envCfg.WebauthnTable),
	}

	results, err := localStorage.client.Scan(params)
	ms.NoError(err, "failed to scan storage for results")

	resultsStr := formatDynamoResults(results)
	ms.Contains(resultsStr, "Count: 3", "initial data wasn't saved properly")

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
			name:            "no credentials",
			user:            testUser0,
			credID:          "missing",
			wantStatus:      http.StatusNotFound,
			wantErrContains: "No webauthn credentials available.",
		},
		{
			name:            "one credential but bad credential ID",
			user:            testUser1,
			credID:          "missing",
			wantErrContains: "Credential not found with id: missing",
			wantCredIDs:     [][]byte{testUser1.Credentials[0].ID},
			wantStatus:      http.StatusNotFound,
		},
		{
			name:           "one credential gets deleted",
			user:           testUser1,
			credID:         hashAndEncodeKeyHandle(testUser1.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			dontWantCredID: testUser1.Credentials[0].ID,
		},
		{
			name:           "two credentials and one is deleted",
			user:           testUser2,
			credID:         hashAndEncodeKeyHandle(testUser2.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			wantContains:   []string{"Count: 3", testUser0.ID, testUser1.ID, testUser2.ID},
			wantCredIDs:    [][]byte{testUser2.Credentials[1].ID},
			dontWantCredID: testUser2.Credentials[0].ID,
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {
			err, status := tt.user.DeleteCredential(tt.credID)

			ms.Equal(tt.wantStatus, status, "incorrect http status")

			if tt.wantErrContains != "" {
				ms.Error(err, "expected an error but didn't get one")
				ms.Contains(err.Error(), tt.wantErrContains, "incorrect error")
				return
			}

			ms.NoError(err, "unexpected error")

			results, err := localStorage.client.Scan(params)
			ms.Error(err, "failed to scan storage for results")

			resultsStr := formatDynamoResults(results)

			for _, w := range tt.wantContains {
				ms.Contains(resultsStr, w, "incorrect db results missing string")
			}

			gotUser := DynamoUser{
				ID:     tt.user.ID,
				ApiKey: tt.user.ApiKey,
				Store:  localStorage,
			}
			gotUser.Load()

			ms.Len(gotUser.Credentials, len(tt.wantCredIDs), "incorrect remaining credential ids")

			for i, w := range tt.wantCredIDs {
				ms.Equal(string(w), string(gotUser.Credentials[i].ID), "incorrect credential id")
			}

			if len(tt.dontWantCredID) == 0 {
				return
			}

			for _, g := range gotUser.Credentials {
				assert.NotEqual(string(tt.dontWantCredID), string(g.ID), "unexpected credential id")
			}
		})
	}
}
