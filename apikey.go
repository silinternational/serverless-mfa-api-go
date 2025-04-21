package mfa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

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
func (k *ApiKey) IsCorrect(given string) error {
	if k.ActivatedAt == 0 {
		return fmt.Errorf("key is not active: %s", k.Key)
	}

	if given == "" {
		return errors.New("secret to compare cannot be empty")
	}

	if k.HashedSecret == "" {
		return errors.New("cannot compare with empty hashed secret")
	}

	err := bcrypt.CompareHashAndPassword([]byte(k.HashedSecret), []byte(given))
	if err != nil {
		return err
	}

	return nil
}

// EncryptData uses the Secret to AES encrypt an arbitrary data block. It does not encrypt the key itself.
func (k *ApiKey) EncryptData(plaintext []byte) ([]byte, error) {
	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return nil, err
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
	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return nil, err
	}

	// plaintext must be as long as ciphertext minus the length of the IV, which is the same as the AES block size
	plaintext := make([]byte, len(ciphertext)-aes.BlockSize)

	// the IV (initialization vector) is the first BlockSize bytes in the encrypted content
	iv := ciphertext[:aes.BlockSize]

	// use CTR to decrypt content, which starts BlockSize bytes into the ciphertext
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}

// EncryptLegacy uses the Secret to AES encrypt an arbitrary data block. This is intended only for legacy data such
// as U2F keys. The returned data is the Base64-encoded IV and the Base64-encoded cipher text separated by a colon.
func (k *ApiKey) EncryptLegacy(plaintext []byte) ([]byte, error) {
	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to create random data for initialization vector: %w", err)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	ivBase64 := base64.StdEncoding.EncodeToString(iv)
	cipherBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return []byte(ivBase64 + ":" + cipherBase64), nil
}

// DecryptLegacy uses the Secret to AES decrypt an arbitrary data block. This is intended only for legacy data such
// as U2F keys.
func (k *ApiKey) DecryptLegacy(ciphertext []byte) ([]byte, error) {
	block, err := newCipherBlock(k.Secret)
	if err != nil {
		return nil, err
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

// ReEncrypt decrypts a data block with an old key, then encrypts the resulting plaintext with a new key
func (k *ApiKey) ReEncrypt(oldKey ApiKey, v *[]byte) error {
	plaintext, err := oldKey.DecryptData(*v)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	newCiphertext, err := k.EncryptData(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	*v = newCiphertext
	return nil
}

// ReEncryptLegacy decrypts a data block with an old key, then encrypts the resulting plaintext with a new key. This
// uses a legacy ciphertext format that is stored as Base64 strings.
func (k *ApiKey) ReEncryptLegacy(oldKey ApiKey, v *string) error {
	plaintext, err := oldKey.DecryptLegacy([]byte(*v))
	if err != nil {
		return err
	}

	newCiphertext, err := k.EncryptLegacy(plaintext)
	if err != nil {
		return err
	}

	*v = string(newCiphertext)
	return nil
}

// ReEncryptTables loads each record that was encrypted using this key, re-encrypts it using the new key, and writes
// the updated data back to the database.
func (k *ApiKey) ReEncryptTables(oldSecret string) error {
	var users []WebauthnUser
	err := k.Store.QueryApiKey(envConfig.WebauthnTable, k.Key, &users)
	if err != nil {
		return fmt.Errorf("failed to query %s table for key %s: %w", envConfig.WebauthnTable, k.Key, err)
	}

	oldKey := *k
	oldKey.Secret = oldSecret
	for _, u := range users {
		err = k.ReEncrypt(oldKey, &u.EncryptedSessionData)
		if err != nil {
			return err
		}

		err = k.ReEncrypt(oldKey, &u.EncryptedCredentials)
		if err != nil {
			return err
		}

		for _, v := range []*string{&u.EncryptedPublicKey, &u.EncryptedKeyHandle, &u.EncryptedAppId} {
			err = k.ReEncryptLegacy(oldKey, v)
		}

		err = u.Store.Store(envConfig.WebauthnTable, &u)
		if err != nil {
			return err
		}
	}
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
		invalidRequest(w, err)
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

	storage, err := getStorageClient(r)
	if err != nil {
		jsonResponse(w, err, http.StatusInternalServerError)
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
		invalidRequest(w, err)
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

	storage, err := getStorageClient(r)
	if err != nil {
		jsonResponse(w, err, http.StatusInternalServerError)
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

// RotateApiKey generates a new secret for an existing key. All data in other tables that is encrypted by the key will
// be re-encrypted using the new secret.
func RotateApiKey(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		ApiKeyValue  string `json:"apiKeyValue"`
		ApiKeySecret string `json:"apiKeySecret"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		invalidRequest(w, err)
		return
	}

	if requestBody.ApiKeyValue == "" {
		jsonResponse(w, fmt.Errorf("apiKeyValue is required"), http.StatusBadRequest)
		return
	}

	if requestBody.ApiKeySecret == "" {
		jsonResponse(w, fmt.Errorf("apiKeySecret is required"), http.StatusBadRequest)
		return
	}

	storage, err := getStorageClient(r)
	if err != nil {
		jsonResponse(w, err, http.StatusInternalServerError)
		return
	}

	key := ApiKey{Key: requestBody.ApiKeyValue, Store: storage}
	err = key.Load()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to load key: %s", err), http.StatusNotFound)
		return
	}

	err = key.IsCorrect(requestBody.ApiKeySecret)
	if err != nil {
		jsonResponse(w, fmt.Errorf("key is not valid: %s", err), http.StatusUnauthorized)
	}

	key.ActivatedAt = 0
	err = key.Activate()
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to activate key: %s", err), http.StatusInternalServerError)
	}

	err = key.ReEncryptTables(requestBody.ApiKeySecret)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to re-encrypt data: %s", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"apiSecret": key.Secret}, http.StatusOK)
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

// newCipherBlock creates a new cipher.Block from a base64-encoded AES key. If the string is not valid base64 data, it
// will be interpreted as binary data.
func newCipherBlock(key string) (cipher.Block, error) {
	var sec []byte
	var err error
	sec, err = base64.StdEncoding.DecodeString(key)
	if err != nil {
		sec = []byte(key)
	}

	block, err := aes.NewCipher(sec)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher: %w", err)
	}
	return block, nil
}
