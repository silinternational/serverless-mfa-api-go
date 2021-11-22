package serverless_mfa_api_go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
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

// Hash - Generate bcrypt hash from Secret and store in HashedSecret
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
		return nil, fmt.Errorf("ciphertext contains more than one colon, does not look like legacy data")
	}

	iv := make([]byte, aes.BlockSize)
	_, err = base64.StdEncoding.Decode(iv, parts[0])
	if err != nil {
		fmt.Printf("unable to decode iv: %s\n", err)
		return nil, err
	}

	decodedCipher, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		fmt.Printf("unable to decode ciphertext: %s\n", err)
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
