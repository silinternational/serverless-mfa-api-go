package main

import (
	"github.com/gin-gonic/gin"
	"github.com/silinternational/serverless-mfa-api-go/u2fsimulator"
)

func main() {
	app := gin.Default()
	app.POST("/u2f/registration", u2fsimulator.U2fRegistration)
	app.Run()
}
