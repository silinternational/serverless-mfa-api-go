package models

import (
	"github.com/silinternational/serverless-mfa-api-go/domain"
	"github.com/silinternational/serverless-mfa-api-go/stores"
)

var DB *stores.Store

func Init() {
	var err error
	DB, err = initStore()
	if err != nil {
		panic("could not initialize database: " + err.Error())
	}
}

func initStore() (*stores.Store, error) {
	return stores.NewStore(domain.Env.AWSConfig)
}
