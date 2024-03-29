package mfa

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MfaSuite struct {
	suite.Suite
	*require.Assertions
}

func (ms *MfaSuite) SetupTest() {
	ms.Assertions = require.New(ms.T())
	if err := initDb(nil); err != nil {
		ms.NoError(err, "error initializing test database")
		return
	}
}

// Test_MfaSuite runs the test suite
func Test_MfaSuite(t *testing.T) {
	ms := &MfaSuite{}

	suite.Run(t, ms)
}
