package serverless_mfa_api_go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"

	"golang.org/x/crypto/bcrypt"
)

const ApiKeyTablePK = "value"

type ApiKey struct {
	Key          string   `json:"value"`
	Secret       string   `json:"-"`
	HashedSecret string   `json:"hashedApiSecret"`
	Email        string   `json:"email"`
	CreatedAt    int      `json:"createdAt"`
	ActivatedAt  int      `json:"activatedAt"`
	Store        *Storage `json:"-"`
}

func (k *ApiKey) Load() error {
	return k.Store.Load(envConfig.ApiKeyTableName, ApiKeyTablePK, k.Key, k)
}

// Generate bcrypt hash from Secret and store in HashedSecret
func (k *ApiKey) Hash() error {
	if k.Secret == "" {
		return errors.New("empty secret cannot be hashed")
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(k.Secret), bcrypt.DefaultCost)
	k.HashedSecret = string(hashedSecret)
	return err
}

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

func (k *ApiKey) Encrypt(plaintext []byte) ([]byte, error) {
	// create cipher block with api secret as aes key
	block, err := aes.NewCipher([]byte(k.Secret))
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
	block, err := aes.NewCipher([]byte(k.Secret))
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
