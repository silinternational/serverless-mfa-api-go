package actions

import "github.com/gin-gonic/gin"

const (
	pathCredential = "/credential"
	pathLogin      = "/login"
	pathRegister   = "/register"
	pathUser       = "/user"
)

const (
	paramUUID       = "uuid"
	paramCredential = "cred"
)

// Attach attaches the routes to the given engine
func App() *gin.Engine {
	app := gin.Default()

	apiKey := app.Group("/api-key")
	apiKey.POST("/", apiKeyCreate)
	apiKey.POST("/activate", apiKeyActivate)

	totp := app.Group("/totp")
	totp.POST("/", totpCreate)
	totp.DELETE("/:"+paramUUID, totpDelete)
	totp.POST("/:"+paramUUID+"/validate", totpValidate)

	webauthn := app.Group("/webauthn")
	webauthn.Use(webauthnAuthenticate())
	webauthn.POST(pathRegister, webauthnBeginRegister)
	webauthn.PUT(pathRegister, webauthnFinishRegister)
	webauthn.POST(pathLogin, webauthnBeginLogin)
	webauthn.PUT(pathLogin, webauthnFinishLogin)
	webauthn.DELETE(pathUser, webauthnDeleteUser)
	webauthn.DELETE(pathCredential+"/:"+paramCredential, webauthnDeleteCredential)

	return app
}

func jsonResponse(c *gin.Context, status int, body any) {
	switch b := body.(type) {
	case error:
		c.AbortWithStatusJSON(status, gin.H{"error": b.Error()})
	default:
		c.JSON(status, body)
	}
}
