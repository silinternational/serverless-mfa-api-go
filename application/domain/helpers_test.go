package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type DomainSuite struct {
	suite.Suite
	*require.Assertions
}

func (ds *DomainSuite) SetupTest() {
	ds.Assertions = require.New(ds.T())
}

// Test_DomainSuite runs the test suite
func Test_DomainSuite(t *testing.T) {
	ds := &DomainSuite{}
	suite.Run(t, ds)
}

func (ds *DomainSuite) Test_HashAndEncode() {
	tests := []string{
		"",
		"abc123",
		"123456890",
		"The quick brown fox jumped over the lazy dog.",
	}

	for i, want := range tests {
		ds.T().Run(fmt.Sprintf("test %d", i+1), func(t *testing.T) {
			wantHash := sha256.Sum256([]byte(want))

			got := HashAndEncode([]byte(want))
			gotHash, err := base64.RawURLEncoding.DecodeString(got)
			ds.NoError(err)

			ds.Equal(wantHash, gotHash)
		})
	}
}

func (ds *DomainSuite) Test_FixStringEncoding() {
	tests := []string{
		"",
		"+/=",
		"there is nothing to remove.",
		"http://hello.world",
		"text1textText/text0textText3textY$text+textText//text_textText;text=",
	}

	for i, want := range tests {
		ds.T().Run(fmt.Sprintf("test %d", i+1), func(t *testing.T) {
			got := FixStringEncoding(want)

			ds.NotContains(got, "+")
			ds.NotContains(got, "/")
			ds.NotContains(got, "=")
		})
	}
}

func (ds *DomainSuite) Test_FixEncoding() {
	tests := []string{
		"+/=",
		"http://hello.world",
		"text1textText/text0textText3textY$text+textText//text_textText;text=",
		"The quick brown fox jumped over the lazy dog.",
	}

	for i, want := range tests {
		ds.T().Run(fmt.Sprintf("test %d", i+1), func(t *testing.T) {
			got := FixEncoding([]byte(want))

			gotB, err := io.ReadAll(got)
			ds.NoError(err)

			want = FixStringEncoding(want)
			ds.Equal([]byte(want), gotB)
		})
	}
}
