package models

import (
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ApiMeta holds metadata about the calling service for use in WebAuthn responses.
// Since this service/api is consumed by multiple sources this information cannot
// be stored in the envConfig
type ApiMeta struct {
	RPDisplayName   string `json:"RPDisplayName"` // Display Name for your site
	RPID            string `json:"RPID"`          // Generally the FQDN for your site
	RPOrigin        string `json:"RPOrigin"`      // The origin URL for WebAuthn requests
	RPIcon          string `json:"RPIcon"`        // Optional icon URL for your site
	UserUUID        string `json:"UserUUID"`
	Username        string `json:"Username"`
	UserDisplayName string `json:"UserDisplayName"`
	UserIcon        string `json:"UserIcon"`
}

func (meta ApiMeta) GetWebAuthn() (*webauthn.WebAuthn, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: meta.RPDisplayName, // Display Name for your site
		RPID:          meta.RPID,          // Generally the FQDN for your site
		RPOrigin:      meta.RPOrigin,      // The origin URL for WebAuthn requests
		RPIcon:        meta.RPIcon,        // Optional icon URL for your site
		Debug:         true,
	})
	if err != nil {
		log.Println(err)
	}

	return web, nil
}
