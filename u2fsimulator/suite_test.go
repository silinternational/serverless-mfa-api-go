package u2fsimulator

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type U2fSuite struct {
	suite.Suite
	*require.Assertions
}

func (us *U2fSuite) SetupTest() {
	us.Assertions = require.New(us.T())
}

// Test_U2fSuite runs the test suite
func Test_U2fSuite(t *testing.T) {
	us := &U2fSuite{}

	suite.Run(t, us)
}
