package actions

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/silinternational/serverless-mfa-api-go/api"
	"github.com/silinternational/serverless-mfa-api-go/models"
	"github.com/silinternational/serverless-mfa-api-go/stores"
)

type TOTP struct {
	ID              string
	EncryptedSecret string
	ApiKey          string
	Store           *stores.Store
}

func totpCreate(c *gin.Context) {
	apiKey, err := getActivatedApiKeyFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusUnauthorized, errUnauthorized)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      c.PostForm("issuer"),
		AccountName: apiKey.Email,
		Algorithm:   otp.AlgorithmSHA256,
	})
	if err != nil {
		jsonResponse(c, http.StatusInternalServerError, err)
		return
	}

	encryptedKey, err := apiKey.Encrypt([]byte(key.Secret()))
	if err != nil {
		jsonResponse(c, http.StatusInternalServerError, err)
		return
	}

	totpID, err := uuid.NewV4()
	if err != nil {
		jsonResponse(c, http.StatusInternalServerError, err)
		return
	}

	t := TOTP{
		ID:              totpID.String(),
		EncryptedSecret: string(encryptedKey),
	}

	if err := t.Store.Create("totp", t); err != nil {
		jsonResponse(c, http.StatusInternalServerError, err)
		return
	}

	response := api.TotpCreateOutput{
		ID:       totpID.String(),
		Key:      key.Secret(),
		AuthURL:  key.URL(),
		ImageURL: "",
	}

	jsonResponse(c, http.StatusOK, response)
}

func totpDelete(c *gin.Context) {
}

func totpValidate(c *gin.Context) {
	apiKey, err := getActivatedApiKeyFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusUnauthorized, errUnauthorized)
		return
	}

	id := c.Param(paramUUID)
	if id == "" {
		jsonResponse(c, http.StatusUnauthorized, errUnauthorized)
		return
	}

	var body api.TotpValidateInput
	if err := c.ShouldBindJSON(&body); err != nil {
		jsonResponse(c, http.StatusBadRequest, fmt.Errorf("code (as a string) is required"))
		return
	}

	// TODO load TOTP
	var t TOTP
	if err := gin.Bind(&t); err != nil {
		jsonResponse(c, http.StatusInternalServerError, errUnauthorized)
		return
	}

	// TODO verify TOTP ApiKey
	if t.ApiKey != apiKey.Key {
		jsonResponse(c, http.StatusUnauthorized, errUnauthorized)
		return
	}

	secret, err := apiKey.Decrypt([]byte(t.EncryptedSecret))
	if err != nil {
		jsonResponse(c, http.StatusInternalServerError, err)
		return
	}

	valid := totp.Validate(body.Code, string(secret))
	if !valid {
		jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("Invalid"))
		return
	}

	jsonResponse(c, http.StatusOK, api.TotpValidateOutput{Message: "Valid"})
}

func getActivatedApiKeyFromContext(c *gin.Context) (*models.ApiKey, error) {
	key := c.GetHeader("x-mfa-apikey")
	secret := c.GetHeader("x-mfa-apisecret")

	return models.GetActivatedApiKey(key, secret)
}
