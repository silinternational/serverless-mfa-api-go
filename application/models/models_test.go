package models

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/silinternational/serverless-mfa-api-go/stores"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ModelSuite struct {
	db       *stores.Store
	webauthn *webauthn.WebAuthn

	suite.Suite
	*require.Assertions
}

func (ms *ModelSuite) SetupTest() {
	ms.Assertions = require.New(ms.T())

	var err error
	if ms.db, err = initStore(); err != nil {
		ms.NoError(err, "error initializing test database")
		return
	}

	if ms.webauthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",
		RPID:          "111.11.11.11",
		Debug:         true,
		RPOrigins:     []string{LocalAppID},
	}); err != nil {
		ms.NoError(err, "error initializing test webauthn client")
		return
	}
}

// Test_ModelSuite runs the test suite
func Test_ModelSuite(t *testing.T) {
	ms := &ModelSuite{}

	suite.Run(t, ms)
}
