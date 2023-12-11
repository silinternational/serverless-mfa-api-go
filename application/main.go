package main

import (
	"log"
	"os"

	"github.com/silinternational/serverless-mfa-api-go/actions"
	"github.com/silinternational/serverless-mfa-api-go/domain"
)

func init() {
	log.SetOutput(os.Stdout)

	domain.Init()
}

func main() {
	app := actions.App()
	app.Run()
}
