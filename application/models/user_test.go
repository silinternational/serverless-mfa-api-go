package models

import (
	"net/http"
	"testing"

	"github.com/silinternational/serverless-mfa-api-go/domain"
)

func (ms *ModelSuite) Test_User_DeleteCredential() {
	users, err := GetTestWebauthnUsers(ms.db, ms.webauthn)
	ms.NoError(err, "did not initialize test users correctly")

	testUser0, testUser1, testUser2 := users[0], users[1], users[2]

	tests := []struct {
		name             string
		user             User
		credID           string
		wantErrContains  string
		wantStatus       int
		wantContains     []string
		dontWantContains string
		wantCredIDs      [][]byte
		dontWantCredID   []byte
	}{
		{
			name:            "no webauthn credentials",
			user:            testUser0,
			credID:          "noMatchingCredID",
			wantStatus:      http.StatusNotFound,
			wantErrContains: "No webauthn credentials available.",
			wantContains:    []string{"encryptedAppId:"},
		},
		{
			name:             "legacy u2f credential",
			user:             testUser0,
			credID:           LegacyU2FCredID,
			wantStatus:       http.StatusNoContent,
			dontWantContains: "encryptedAppId:",
		},
		{
			name:            "one credential but bad credential ID",
			user:            testUser1,
			credID:          "badCredID",
			wantErrContains: "Credential not found with id: badCredID",
			wantCredIDs:     [][]byte{testUser1.Credentials[0].ID},
			wantStatus:      http.StatusNotFound,
		},
		{
			name:           "one credential gets deleted",
			user:           testUser1,
			credID:         domain.HashAndEncode(testUser1.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			dontWantCredID: testUser1.Credentials[0].ID,
		},
		{
			name:           "two credentials and one is deleted",
			user:           testUser2,
			credID:         domain.HashAndEncode(testUser2.Credentials[0].ID),
			wantStatus:     http.StatusNoContent,
			wantContains:   []string{"Count: 3", testUser0.ID, testUser1.ID, testUser2.ID},
			wantCredIDs:    [][]byte{testUser2.Credentials[1].ID},
			dontWantCredID: testUser2.Credentials[0].ID,
		},
	}
	for _, tt := range tests {
		ms.T().Run(tt.name, func(t *testing.T) {
			status, err := tt.user.DeleteCredential(tt.credID)

			ms.Equal(tt.wantStatus, status, "incorrect http status")

			if tt.wantErrContains != "" {
				ms.Error(err, "expected an error but didn't get one")
				ms.Contains(err.Error(), tt.wantErrContains, "incorrect error")
			} else {
				ms.NoError(err, "unexpected error")
			}

			results, err := ms.db.ScanTable(domain.Env.WebauthnTable)
			ms.NoError(err, "failed to scan storage for results")

			resultsStr := FormatDynamoResults(results)

			for _, w := range tt.wantContains {
				ms.Contains(resultsStr, w, "incorrect db results missing string")
			}

			if tt.dontWantContains != "" {
				ms.NotContainsf(resultsStr, tt.dontWantContains, "unexpected string included in results")
			}

			gotUser := User{
				ID:     tt.user.ID,
				ApiKey: tt.user.ApiKey,
				Store:  ms.db,
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
				ms.NotEqual(string(tt.dontWantCredID), string(g.ID), "unexpected credential id")
			}
		})
	}
}
