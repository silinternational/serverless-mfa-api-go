package actions

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/silinternational/serverless-mfa-api-go/domain"
	"github.com/silinternational/serverless-mfa-api-go/models"
	"github.com/silinternational/serverless-mfa-api-go/stores"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const localAppID = "http://localhost"

type ActionSuite struct {
	DB       *stores.Store
	router   *gin.Engine
	webauthn *webauthn.WebAuthn

	suite.Suite
	*require.Assertions
}

func (as *ActionSuite) SetupTest() {
	as.Assertions = require.New(as.T())

	var err error
	as.DB, err = stores.NewStore(domain.Env.AWSConfig)
	as.NoError(err, "failed creating local storage for test")

	if as.webauthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "TestRPName",
		RPID:          "111.11.11.11",
		Debug:         true,
		RPOrigins:     []string{models.LocalAppID},
	}); err != nil {
		as.NoError(err, "error initializing test webauthn client")
		return
	}
}

// Test_ActionSuite runs the test suite
func Test_ActionSuite(t *testing.T) {
	as := &ActionSuite{
		router: App(),
	}

	suite.Run(t, as)
}
