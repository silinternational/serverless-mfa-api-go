package mfa

type TOTP struct {
	UUID             string `dynamodbav:"uuid" json:"uuid"`
	ApiKey           string `dynamodbav:"apiKey" json:"apiKey"`
	EncryptedTotpKey string `dynamodbav:"encryptedTotpKey" json:"encryptedTotpKey"`
}
