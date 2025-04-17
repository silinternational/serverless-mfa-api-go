package mfa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"golang.org/x/crypto/bcrypt"
)

// ApiKeyTablePK is the primary key in the ApiKey DynamoDB table
const ApiKeyTablePK = "value"

// ApiKey holds API key data from DynamoDB
type ApiKey struct {
	Key          string   `dynamodbav:"value" json:"value"`
	Secret       string   `dynamodbav:"-" json:"-"`
	HashedSecret string   `dynamodbav:"hashedApiSecret" json:"hashedApiSecret"`
	Email        string   `dynamodbav:"email" json:"email"`
	CreatedAt    int      `dynamodbav:"createdAt" json:"createdAt"`
	ActivatedAt  int      `dynamodbav:"activatedAt" json:"activatedAt"`
	Store        *Storage `dynamodbav:"-" json:"-"`
}

// Load refreshes an ApiKey from the database record
func (k *ApiKey) Load() error {
	return k.Store.Load(envConfig.ApiKeyTable, ApiKeyTablePK, k.Key, k)
}

// Save an ApiKey to the database
func (k *ApiKey) Save() error {
	return k.Store.Store(envConfig.ApiKeyTable, k)
}

// Hash generates a bcrypt hash from the Secret field and stores it in HashedSecret
func (k *ApiKey) Hash() error {
	if k.Secret == "" {
		return errors.New("empty secret cannot be hashed")
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(k.Secret), bcrypt.DefaultCost)
	k.HashedSecret = string(hashedSecret)
	return err
}

// IsCorrect returns true if and only if the given string is a match for HashedSecret
func (k *ApiKey) IsCorrect(given string) (bool, error) {
	if given == "" {
		return false, errors.New("secret to compare cannot be empty")
	}
	if k.HashedSecret == "" {
		return false, errors.New("cannot compare with empty hashed secret")
	}

	err := bcrypt.CompareHashAndPassword([]byte(k.HashedSecret), []byte(given))
	if err != nil {
		return false, err
	}

	return true, nil
}

// EncryptData uses the Secret to AES encrypt an arbitrary data block. It does not encrypt the key itself.
func (k *ApiKey) EncryptData(plaintext []byte) ([]byte, error) {
	var sec []byte
	var err error
	sec, err = base64.StdEncoding.DecodeString(k.Secret)
	if err != nil {
		sec = []byte(k.Secret)
	}
	// create cipher block with api secret as aes key
	block, err := aes.NewCipher(sec)
	if err != nil {
		return []byte{}, err
	}

	// byte array to hold encrypted content
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// The IV needs to be unique, but not secure. Therefore, it's common to
	// include it at the beginning of the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	// use CTR to encrypt plaintext
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// DecryptData uses the Secret to AES decrypt an arbitrary data block. It does not decrypt the key itself.
func (k *ApiKey) DecryptData(ciphertext []byte) ([]byte, error) {
	var sec []byte
	var err error
	sec, err = base64.StdEncoding.DecodeString(k.Secret)
	if err != nil {
		sec = []byte(k.Secret)
	}

	block, err := aes.NewCipher(sec)
	if err != nil {
		return []byte{}, errors.Wrap(err, "failed to create new cipher")
	}

	// plaintext will hold decrypted content, it must be at least as long
	// as ciphertext or decryption process will panic
	plaintext := make([]byte, len(ciphertext))

	// get iv from encrypted content
	iv := ciphertext[:aes.BlockSize]

	// use CTR to decrypt content
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}

// DecryptLegacy uses the Secret to AES decrypt an arbitrary data block. This is intended only for legacy data such
// as U2F keys.
func (k *ApiKey) DecryptLegacy(ciphertext []byte) ([]byte, error) {
	var sec []byte
	var err error
	sec, err = base64.StdEncoding.DecodeString(k.Secret)
	if err != nil {
		sec = []byte(k.Secret)
	}

	block, err := aes.NewCipher(sec)
	if err != nil {
		return []byte{}, errors.Wrap(err, "failed to create new cipher")
	}

	// data was encrypted, then base64 encoded, then joined with a :, need to split
	// on :, then decode first part as iv and second as encrypted content
	parts := bytes.Split(ciphertext, []byte(":"))
	if len(parts) != 2 {
		return nil, fmt.Errorf("ciphertext does not look like legacy data")
	}

	iv := make([]byte, aes.BlockSize)
	_, err = base64.StdEncoding.Decode(iv, parts[0])
	if err != nil {
		fmt.Printf("failed to decode iv: %s\n", err)
		return nil, err
	}

	decodedCipher, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		fmt.Printf("failed to decode ciphertext: %s\n", err)
		return nil, err
	}

	// plaintext will hold decrypted content, it must be at least as long
	// as ciphertext or decryption process will panic
	plaintext := make([]byte, len(decodedCipher))

	// use CTR to decrypt content
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, decodedCipher)

	return plaintext, nil
}

// Activate an ApiKey. Creates a random string for the key secret and updates the Secret, HashedSecret, and
// ActivatedAt fields.
func (k *ApiKey) Activate() error {
	if k.ActivatedAt != 0 {
		return errors.New("key already activated")
	}

	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return fmt.Errorf("failed to create random secret: %w", err)
	}

	k.Secret = base64.StdEncoding.EncodeToString(random)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(k.Secret), 10)
	if err != nil {
		return fmt.Errorf("failed to hash secret: %w", err)
	}

	k.HashedSecret = string(hashedSecret)
	k.ActivatedAt = int(time.Now().UTC().Unix() * 1000)
	return nil
}

// ActivateApiKey is the handler for the POST /api-key/activate endpoint. It creates the key secret and updates the
// database record.
func ActivateApiKey(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		ApiKeyValue string `json:"apiKeyValue"`
		Email       string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		jsonResponse(w, fmt.Errorf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	if requestBody.ApiKeyValue == "" {
		jsonResponse(w, fmt.Errorf("apiKeyValue is required"), http.StatusBadRequest)
		return
	}

	if requestBody.Email == "" {
		jsonResponse(w, fmt.Errorf("email is required"), http.StatusBadRequest)
		return
	}

	storage, ok := r.Context().Value(StorageContextKey).(*Storage)
	if !ok {
		jsonResponse(w, fmt.Errorf("no storage client found in context"), http.StatusInternalServerError)
		return
	}

	newKey := ApiKey{Key: requestBody.ApiKeyValue, Store: storage}
	err = newKey.Load()
	if err != nil {
		jsonResponse(w, fmt.Errorf("key not found: %s", err), http.StatusNotFound)
		return
	}

	err = newKey.Activate()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to activate key: %s", err), http.StatusBadRequest)
		return
	}

	err = newKey.Save()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to save key: %s", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"apiSecret": newKey.Secret}, http.StatusOK)
}

// CreateApiKey is the handler for the POST /api-key endpoint. It creates a new API Key and saves it to the database.
func CreateApiKey(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Email string `json:"email"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		jsonResponse(w, fmt.Errorf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	if requestBody.Email == "" {
		jsonResponse(w, fmt.Errorf("email is required"), http.StatusBadRequest)
		return
	}

	key, err := NewApiKey(requestBody.Email)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to create a random key: %s", err), http.StatusInternalServerError)
		return
	}

	storage, ok := r.Context().Value(StorageContextKey).(*Storage)
	if !ok {
		jsonResponse(w, fmt.Errorf("no storage client found in context"), http.StatusInternalServerError)
		return
	}
	key.Store = storage

	err = key.Save()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to save key: %s", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, nil, http.StatusNoContent)
}

// NewApiKey creates a new key with a random value
func NewApiKey(email string) (ApiKey, error) {
	random := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return ApiKey{}, err
	}

	key := ApiKey{
		Key:       hex.EncodeToString(random),
		Email:     email,
		CreatedAt: int(time.Now().UTC().Unix() * 1000),
	}
	return key, nil
}
