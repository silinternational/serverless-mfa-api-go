package actions

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/silinternational/serverless-mfa-api-go/api"
	"github.com/silinternational/serverless-mfa-api-go/domain"
	"github.com/silinternational/serverless-mfa-api-go/models"
)

// swagger:operation POST /webauthn/register WebAuthN BeginRegister
// ---
//
//	summary: BeginRegister
//	description: |-
//	  Begin WebAuthn registration
//	responses:
//	  '200':
//	    description: the webauthn begin registration result
//	    schema:
//	      "$ref": "#/definitions/WebAuthnBeginRegistrationOutput"
func webauthnBeginRegister(c *gin.Context) {
	user, err := getUserFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	// If user.id is empty, treat as new user/registration
	if user.ID == "" {
		uid, _ := uuid.NewV4()
		user.ID = uid.String()
	}

	// TODO move this here?
	options, err := user.BeginRegistration()
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, fmt.Errorf("failed to begin registration: %w", err))
		return
	}

	response := api.WebAuthnBeginRegistrationOutput{
		user.ID,
		*options,
	}

	c.JSON(http.StatusOK, response)
}

// swagger:operation PUT /webauthn/register WebAuthN FinishRegister
// ---
//
//	summary: FinishRegister
//	description: |-
//	  Finish WebAuthn registration
//	responses:
//	  '200':
//	    description: the webauthn finish registration result
//	    schema:
//	      "$ref": "#/definitions/WebAuthnFinishRegistrationOutput"
func webauthnFinishRegister(c *gin.Context) {
	user, err := getUserFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	// TODO move this here?
	keyHandleHash, err := user.FinishRegistration(c.Request)
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	response := api.WebAuthnFinishRegistrationOutput{
		KeyHandleHash: keyHandleHash,
	}

	jsonResponse(c, http.StatusOK, response)
}

// swagger:operation POST /webauthn/login WebAuthN BeginLogin
// ---
//
//	summary: BeginLogin
//	description: |-
//	  Begin WebAuthn login
//	responses:
//	  '200':
//	    description: the webauthn begin login result
//	    schema:
//	      "$ref": "#/definitions/WebAuthnBeginLoginOutput"
func webauthnBeginLogin(c *gin.Context) {
	user, err := getUserFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	// TODO move this here?
	options, err := user.BeginLogin()
	if err != nil {
		log.Println("error beginning user login:", err)
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	c.JSON(http.StatusOK, options)
}

// swagger:operation PUT /webauthn/login WebAuthN FinishLogin
// ---
//
//	summary: FinishLogin
//	description: |-
//	  Finish WebAuthn Login
//	parameters:
//	  - name: input
//	    in: body
//	    description: parameters for the Audit Run
//	    required: true
//	    schema:
//	      "$ref": "#/definitions/AuditRunInput"
//	responses:
//	  '200':
//	    description: the webauthn finish login result
//	    schema:
//	      "$ref": "#/definitions/WebAuthnFinishLoginOutput"
func webauthnFinishLogin(c *gin.Context) {
	user, err := getUserFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	// TODO move this here?
	credential, err := user.FinishLogin(c.Request)
	if err != nil {
		log.Println("error finishing user login:", err)
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	response := api.WebAuthnFinishLoginOutput{
		KeyHandleHash: domain.HashAndEncode(credential.ID),
	}

	c.JSON(http.StatusBadRequest, response)
}

// swagger:operation DELETE /webauthn/user/{id} WebAuthN DeleteUser
// ---
//
//	summary: DeleteUser
//	description: |-
//	  Delete WebAuthN User
//	parameters:
//	  - name: id
//	    in: path
//	    required: true
//	    description: user ID
//	responses:
//	  '204':
//	    description: OK but no content in response
func webauthnDeleteUser(c *gin.Context) {
	user, err := getUserFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	if err := user.Delete(); err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		log.Println("error deleting user:", err)
		return
	}

	c.Status(http.StatusNoContent)
}

// swagger:operation DELETE /webauthn/credential/{id} WebAuthN DeleteCredential
// ---
//
//	summary: DeleteCredential
//	description: |-
//	  Delete WebAuthN credential
//	parameters:
//	  - name: id
//	    in: path
//	    required: true
//	    description: credential ID
//	responses:
//	  '204':
//	    description: OK but no content in response
func webauthnDeleteCredential(c *gin.Context) {
	user, err := getUserFromContext(c)
	if err != nil {
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	credID := c.Param(paramCredential)
	if credID == "" {
		err := fmt.Errorf("id path parameter not provided to DeleteCredential")
		log.Println(err)
		jsonResponse(c, http.StatusBadRequest, err)
		return
	}

	status, err := user.DeleteCredential(credID)
	if err != nil {
		log.Println("error deleting user credential:", err)
		jsonResponse(c, status, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// webauthnAuthenticate retrieves data from headers and sets the user in context
func webauthnAuthenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// get key and secret from headers
		key := c.GetHeader("x-mfa-apikey")
		secret := c.GetHeader("x-mfa-apisecret")

		if key == "" || secret == "" {
			jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("x-mfa-apikey and x-mfa-apisecret are required"))
			return
		}

		log.Printf("API called by key: %s. %s %s", key, c.Request.Method, c.Request.RequestURI)

		apiKey := models.ApiKey{
			Key:    key,
			Secret: secret,
			Store:  models.DB,
		}

		if err := apiKey.Load(); err != nil {
			jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("failed to load api key: %w", err))
			return
		}

		if apiKey.ActivatedAt == 0 {
			jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("api call attempted for not yet activated key: %s", apiKey.Key))
			return
		}

		valid, err := apiKey.IsCorrect(secret)
		if err != nil {
			jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("failed to validate api key: %w", err))
			return
		}

		if !valid {
			jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("invalid api secret for key %s: %w", key, err))
			return
		}

		// apiMeta includes info about the user and webauthn config
		var apiMeta api.Meta
		if err := c.ShouldBindHeader(&apiMeta); err != nil {
			msg := fmt.Errorf("unable to retrieve api meta information from request: %w", err)
			log.Println(msg)
			jsonResponse(c, http.StatusUnauthorized, msg)
			return
		}

		webAuthnClient, err := apiMeta.GetWebAuthn()
		if err != nil {
			jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("unable to create webauthn client from api meta config: %w", err))
			return
		}

		user := models.NewUser(apiMeta, models.DB, apiKey, webAuthnClient)

		// If this user exists (api key value is not empty), make sure the calling API Key owns the user and is allowed to operate on it
		if user.ApiKeyValue != "" && user.ApiKeyValue != apiKey.Key {
			log.Printf("api key %s tried to access user %s but that user does not belong to that api key", apiKey.Key, user.ID)
			jsonResponse(c, http.StatusUnauthorized, fmt.Errorf("user does not exist"))
			return
		}

		c.Set(domain.UserContextKey, user)
		c.Next()
	}
}

func getUserFromContext(c *gin.Context) (*models.User, error) {
	user, ok := c.Value(domain.UserContextKey).(*models.User)
	if !ok {
		return nil, fmt.Errorf("unable to get user from request context")
	}
	return user, nil
}
