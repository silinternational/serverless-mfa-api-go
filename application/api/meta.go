package api

import (
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Meta holds metadata about the calling service for use in WebAuthn responses.
// Since this service/api is consumed by multiple sources this information cannot
// be stored in the envConfig
type Meta struct {
	RPDisplayName   string `json:"RPDisplayName" header:"x-mfa-RPDisplayName" binding:"required"` // Display Name for your site
	RPID            string `json:"RPID" header:"x-mfa-RPID" binding:"required"`                   // Generally the FQDN for your site
	RPOrigin        string `json:"RPOrigin" header:"x-mfa-RPOrigin"`                              // The origin URL for WebAuthn requests
	RPIcon          string `json:"RPIcon" header:"x-mfa-RPIcon"`                                  // Optional icon URL for your site
	UserUUID        string `json:"UserUUID" header:"x-mfa-UserUUID"`
	Username        string `json:"Username" header:"x-mfa-Username" binding:"required"`
	UserDisplayName string `json:"UserDisplayName" header:"x-mfa-UserDisplayName" binding:"required"`
	UserIcon        string `json:"UserIcon" header:"x-mfa-UserIcon"`
}

func (meta Meta) GetWebAuthn() (*webauthn.WebAuthn, error) {
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
