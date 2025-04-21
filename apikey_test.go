package mfa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestApiKey_IsCorrect(t *testing.T) {
	tests := []struct {
		name         string
		HashedSecret string
		Given        string
		wantErr      bool
	}{
		{
			name:         "valid secret",
			HashedSecret: "$2y$10$Y.FlUK8q//DfybgFzNG2lONaJwvEFxHnCRo/r60BZbITDT6rOUhGa",
			Given:        "abc123",
			wantErr:      false,
		},
		{
			name:         "invalid secret",
			HashedSecret: "$2y$10$Y.FlUK8q//DfybgFzNG2lONaJwvEFxHnCRo/r60BZbITDT6rOUhGa",
			Given:        "123abc",
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ApiKey{
				HashedSecret: tt.HashedSecret,
			}
			err := k.IsCorrect(tt.Given)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsCorrect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

// TestApiKey_Hash - test that hashed secret can be verified
func TestApiKey_Hash(t *testing.T) {
	tests := []struct {
		name    string
		Secret  string
		wantErr bool
	}{
		{
			name:    "matching hash",
			Secret:  "abc123",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ApiKey{
				Secret: tt.Secret,
			}
			err := k.Hash()
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(k.HashedSecret) == 0 {
				t.Error("hashed secret is empty after call to hash")
				return
			}
			err = k.IsCorrect(tt.Secret)
			if err != nil {
				t.Errorf("hashed password not valid after hashing??? error: %s", err)
				return
			}
		})
	}
}

func TestApiKey_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		plaintext []byte
		wantErr   bool
	}{
		{
			name:      "test encrypt/decrypt",
			secret:    "ED86600E-3DBF-4C23-A0DA-9C55D448",
			plaintext: []byte("this is a plaintext string to be encrypted"),
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k1 := &ApiKey{
				Secret: tt.secret,
			}
			k2 := &ApiKey{
				Secret: tt.secret,
			}

			encrypted, err := k1.EncryptData(tt.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			decrypted, err := k2.DecryptData(encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !bytes.Equal(tt.plaintext, decrypted) {
				t.Errorf("results from decypt do not match expected. Got: %s, wanted: %s", decrypted, tt.plaintext)
				return
			}
		})
	}
}

func (ms *MfaSuite) TestApiKeyActivate() {
	notActive := ApiKey{
		Key:       "0000000000000000000000000000000000000000",
		Email:     "email@example.com",
		CreatedAt: 1744788331000,
	}
	active := notActive
	active.ActivatedAt = 1744788394000

	tests := []struct {
		name    string
		key     ApiKey
		wantErr bool
	}{
		{
			name:    "not active",
			key:     notActive,
			wantErr: false,
		},
		{
			name:    "already activated",
			key:     active,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			key := tt.key
			err := key.Activate()
			if tt.wantErr {
				ms.Error(err)
				return
			}

			ms.NoError(err)
			ms.Regexp(regexp.MustCompile("[A-Za-z0-9+/]{43}="), key.Secret)
			ms.NoError(bcrypt.CompareHashAndPassword([]byte(key.HashedSecret), []byte(key.Secret)))
			ms.WithinDuration(time.Now(), time.Unix(int64(key.ActivatedAt/1000), 0), time.Minute)

			// ensure no other fields were changed
			ms.Equal(tt.key.Key, key.Key)
			ms.Equal(tt.key.Email, key.Email)
			ms.Equal(tt.key.CreatedAt, key.CreatedAt)
		})
	}
}

func (ms *MfaSuite) TestActivateApiKey() {
	awsConfig := testAwsConfig()
	testEnvConfig(awsConfig)
	localStorage, err := NewStorage(awsConfig)
	must(err)

	key1 := ApiKey{Key: "key1"}
	must(localStorage.Store(envConfig.ApiKeyTable, &key1))
	key2 := ApiKey{Key: "key2", ActivatedAt: 1744799134000}
	must(localStorage.Store(envConfig.ApiKeyTable, &key2))
	key3 := ApiKey{Key: "key3"}
	must(localStorage.Store(envConfig.ApiKeyTable, &key3))

	tests := []struct {
		name       string
		body       any
		wantStatus int
		wantError  string
	}{
		{
			name: "not previously activated",
			body: map[string]interface{}{
				"email":       "email@example.com",
				"apiKeyValue": key1.Key,
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "already activated",
			body: map[string]interface{}{
				"email":       "email@example.com",
				"apiKeyValue": key2.Key,
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "failed to activate key: key already activated",
		},
		{
			name: "missing email",
			body: map[string]interface{}{
				"apiKeyValue": key3.Key,
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "email is required",
		},
		{
			name: "missing apiKey",
			body: map[string]interface{}{
				"email": "email@example.com",
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "apiKeyValue is required",
		},
		{
			name: "key not found",
			body: map[string]interface{}{
				"email":       "email@example.com",
				"apiKeyValue": "not a key",
			},
			wantStatus: http.StatusNotFound,
			wantError:  "key not found: item does not exist: not a key",
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			res := &lambdaResponseWriter{Headers: http.Header{}}
			req := requestWithUser(tt.body, ApiKey{Store: localStorage})
			ActivateApiKey(res, req)

			if tt.wantStatus != http.StatusOK {
				ms.Equal(tt.wantStatus, res.Status, fmt.Sprintf("response: %s", res.Body))
				var se simpleError
				ms.decodeBody(res.Body, &se)
				ms.Equal(tt.wantError, se.Error)
				return
			}

			ms.Equal(http.StatusOK, res.Status, fmt.Sprintf("response: %s", res.Body))

			var response struct {
				ApiSecret string `json:"apiSecret"`
			}
			ms.NoError(json.Unmarshal(res.Body, &response))
			ms.Len(response.ApiSecret, 44)
		})
	}
}

func (ms *MfaSuite) TestCreateApiKey() {
	awsConfig := testAwsConfig()
	testEnvConfig(awsConfig)
	localStorage, err := NewStorage(awsConfig)
	must(err)

	tests := []struct {
		name       string
		body       any
		wantStatus int
		wantError  string
	}{
		{
			name: "success",
			body: map[string]interface{}{
				"email": "email@example.com",
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "missing email",
			body:       map[string]interface{}{},
			wantStatus: http.StatusBadRequest,
			wantError:  "email is required",
		},
	}
	for _, tt := range tests {
		ms.Run(tt.name, func() {
			res := &lambdaResponseWriter{Headers: http.Header{}}
			req := requestWithUser(tt.body, ApiKey{Store: localStorage})
			CreateApiKey(res, req)

			if tt.wantError != "" {
				ms.Equal(tt.wantStatus, res.Status, fmt.Sprintf("response: %s", res.Body))
				var se simpleError
				ms.decodeBody(res.Body, &se)
				ms.Equal(tt.wantError, se.Error)
				return
			}

			ms.Equal(tt.wantStatus, res.Status, fmt.Sprintf("response: %s", res.Body))
		})
	}
}

func (ms *MfaSuite) TestNewApiKey() {
	got, err := NewApiKey("email@example.com")
	ms.NoError(err)
	ms.Regexp(regexp.MustCompile("[a-f0-9]{40}"), got)
}
