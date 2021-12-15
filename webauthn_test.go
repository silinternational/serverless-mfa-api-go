package mfa

import (
	"testing"

	"github.com/duo-labs/webauthn/protocol"
)

func Test_Parse(t *testing.T) {
	body := `{"rawId":"kCvEeC0h5T4cmnggaesuj2rpiOloBbtRMuGhBUEHmAOHDTPW9pf5ZkXZtm8OQ7HSYT6XnL0W21rrLvWaVGSzag==","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEd/SocWgnCorN52AiYfEj3abYOxgwLEwK3G2/Pk5e83NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQJArxHgtIeU+HJp4IGnrLo9q6YjpaAW7UTLhoQVBB5gDhw0z1vaX+WZF2bZvDkOx0mE+l5y9Ftta6y71mlRks2qlAQIDJiABIVggEroUOB+o5SMLdlfIH1E/UJ8sB3sQkrkGpQlo5BSvh+MiWCDnPHY/oEFqXtlAjZTfIPkUCeamWxhHFwLDlplmfccx4w==","getTransports":{},"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJkNWtidXR6MHhSMEJUVkc0eUpWRjRBbHNTZjBSUTFCcGVYSlQwQmtQY3RBIiwiZXh0cmFfa2V5c19tYXlfYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Lmd0aXMuZ3VydSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ=="},"getClientExtensionResults":{},"id":"kCvEeC0h5T4cmnggaesuj2rpiOloBbtRMuGhBUEHmAOHDTPW9pf5ZkXZtm8OQ7HSYT6XnL0W21rrLvWaVGSzag","type":"public-key"}`

	newReader := fixEncoding([]byte(body))

	_, err := protocol.ParseCredentialCreationResponseBody(newReader)
	if err != nil {
		t.Errorf("error: %+v", err)
	}
}
