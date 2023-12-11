package models

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/silinternational/serverless-mfa-api-go/domain"
	"github.com/silinternational/serverless-mfa-api-go/stores"
	"golang.org/x/crypto/bcrypt"
)

const ApiKeyTablePK = "value"

type ApiKey struct {
	Key          string        `json:"value"`
	Secret       string        `json:"-"`
	HashedSecret string        `json:"hashedApiSecret"`
	Email        string        `json:"email"`
	CreatedAt    int           `json:"createdAt"`
	ActivatedAt  int           `json:"activatedAt"`
	Store        *stores.Store `json:"-"`
}

func NewApiKey(email string) (*ApiKey, error) {
	localStorage, err := initStore()
	if err != nil {
		return nil, fmt.Errorf("error initializing storage: %w", err)
	}

	key := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	apiKey := ApiKey{
		Key:       hex.EncodeToString(key),
		Email:     email,
		CreatedAt: int(time.Now().UTC().UnixMilli()),
	}

	if err = localStorage.Create(domain.Env.ApiKeyTable, apiKey); err != nil {
		return nil, err
	}

	return &apiKey, nil
}

func GetApiKey(key string) (*ApiKey, error) {
	localStorage, err := initStore()
	if err != nil {
		return nil, fmt.Errorf("error initializing storage: %w", err)
	}

	apiKey := ApiKey{
		Key:   key,
		Store: localStorage,
	}

	err = apiKey.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load api key: %w", err)
	}

	return &apiKey, nil
}

func GetActivatedApiKey(key, secret string) (*ApiKey, error) {
	apiKey, err := GetApiKey(key)
	if err != nil {
		return nil, err
	}

	if apiKey.ActivatedAt == 0 {
		return nil, fmt.Errorf("api call attempted for not yet activated key: %s", apiKey.Key)
	}

	valid, err := apiKey.IsCorrect(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to validate api key: %w", err)
	}

	if !valid {
		return nil, fmt.Errorf("invalid api secret for key %s: %w", key, err)
	}

	return apiKey, nil
}

func (k *ApiKey) Activate() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	k.Secret = base64.StdEncoding.EncodeToString(b)
	k.ActivatedAt = int(time.Now().UTC().UnixMilli())
	k.Hash()

	if err := k.Store.Save(domain.Env.ApiKeyTable, k); err != nil {
		return "", err
	}

	return k.Secret, nil
}

func (k *ApiKey) Load() error {
	return (*k.Store).Load(domain.Env.ApiKeyTable, ApiKeyTablePK, k.Key, k)
}

// Hash - Generate bcrypt hash from Secret and store in HashedSecret
func (k *ApiKey) Hash() error {
	if k.Secret == "" {
		return ErrEmptySecret
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(k.Secret), bcrypt.DefaultCost)
	k.HashedSecret = string(hashedSecret)
	return err
}

func (k *ApiKey) IsCorrect(given string) (bool, error) {
	if given == "" {
		return false, ErrEmptyCompareSecret
	}
	if k.HashedSecret == "" {
		return false, ErrEmptyHashedSecret
	}

	err := bcrypt.CompareHashAndPassword([]byte(k.HashedSecret), []byte(given))
	return err == nil, err
}

func (k *ApiKey) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := k.newCipher()
	if err != nil {
		return []byte{}, err
	}

	// byte array to hold encrypted content
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// The IV needs to be unique, but not secure. Therefore it's common to
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

func (k *ApiKey) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := k.newCipher()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create new cipher: %w", err)
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

func (k *ApiKey) DecryptLegacy(ciphertext []byte) ([]byte, error) {
	block, err := k.newCipher()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create new cipher: %w", err)
	}

	// data was encrypted, then base64 encoded, then joined with a semicolon
	// 1) split on semicolon
	parts := bytes.Split(ciphertext, []byte{':'})
	if len(parts) != 2 {
		return nil, ErrInvalidLegacyData
	}

	// 2) decode first part as iv
	iv := make([]byte, aes.BlockSize)
	_, err = base64.StdEncoding.Decode(iv, parts[0])
	if err != nil {
		return nil, fmt.Errorf("unable to decode iv: %w", err)
	}

	// 3) decode second part as encrypted content
	decodedCipher, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("unable to decode ciphertext: %w", err)
	}

	// plaintext will hold decrypted content, it must be at least as long
	// as ciphertext or decryption process will panic
	plaintext := make([]byte, len(decodedCipher))

	// use CTR to decrypt content
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, decodedCipher)

	return plaintext, nil
}

func (k *ApiKey) newCipher() (cipher.Block, error) {
	sec, err := base64.StdEncoding.DecodeString(k.Secret)
	if err != nil {
		sec = []byte(k.Secret)
	}
	return aes.NewCipher(sec)
}
