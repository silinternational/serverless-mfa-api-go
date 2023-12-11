package actions

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/silinternational/serverless-mfa-api-go/api"
	"github.com/silinternational/serverless-mfa-api-go/models"
)

func apiKeyCreate(c *gin.Context) {
	var body api.ApiKeyCreateInput
	if err := c.ShouldBindJSON(&body); err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	if _, err := models.NewApiKey(body.Email); err != nil {
		jsonResponse(c, http.StatusInternalServerError, err)
		return
	}

	c.Status(http.StatusNoContent)
}

func apiKeyActivate(c *gin.Context) {
	var body api.ApiKeyActivateInput
	if err := c.ShouldBindJSON(&body); err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	apiKey, err := models.GetApiKey(body.ApiKey)
	if err != nil {
		jsonResponse(c, http.StatusInternalServerError, errInternalServerError)
		return
	}

	if apiKey.Email != body.Email {
		jsonResponse(c, http.StatusNotFound, fmt.Errorf("no matching api key record was found"))
		return
	}

	if apiKey.ActivatedAt > 0 {
		log.Printf("Attempt to re-activate API Key %s...\n", body.ApiKey[:len(body.ApiKey)/2])
		jsonResponse(c, http.StatusUnauthorized, errUnauthorized)
		return
	}

	secret, err := apiKey.Activate()
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, errInternalServerError)
	}

	jsonResponse(c, http.StatusOK, api.ApiKeyActivateOutput{Secret: secret})
}
