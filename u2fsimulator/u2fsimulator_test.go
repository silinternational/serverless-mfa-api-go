package u2fsimulator

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type httpResponseWriter struct {
	Body    []byte
	Headers http.Header
	Status  int
}

func newHttpResponseWriter() *httpResponseWriter {
	return &httpResponseWriter{
		Headers: http.Header{},
	}
}
func (l *httpResponseWriter) Header() http.Header {
	return l.Headers
}

func (l *httpResponseWriter) Write(contents []byte) (int, error) {
	// If WriteHeader has not been called, Write is supposed to set default status code
	if l.Status == 0 {
		l.Status = http.StatusOK
	}

	l.Body = append(l.Body, contents...)
	return len(l.Body), nil
}

func (l *httpResponseWriter) WriteHeader(statusCode int) {
	l.Status = statusCode
}

func (us *U2fSuite) Test_U2fRegistration() {

	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"

	rpID := "http://ourTestApp"

	httpWriter := newHttpResponseWriter()
	requestBody, err := json.Marshal(map[string]string{
		"challenge": challenge,
	})
	us.NoError(err, "error just creating body params for test")

	httpRequest, err := http.NewRequest(http.MethodPost, "https://example.com", bytes.NewBuffer(requestBody))
	us.NoError(err, "error just creating http request for test")

	httpRequest.Header.Set("x-mfa-UserUUID", "the-id-of-the-dynamo-user")
	httpRequest.Header.Set("x-mfa-RPID", rpID)
	httpRequest.Header.Set("x-mfa-RPOrigin", rpID)

	U2fRegistration(httpWriter, httpRequest)

	gotBody := string(httpWriter.Body)
	us.Contains(gotBody, `"id":"`)
	us.Contains(gotBody, `"rawId":"`)
	us.Contains(gotBody, `"response":{"authenticatorData":"`)
	us.Contains(gotBody, `"attestationObject":"`)
	us.Contains(gotBody, `"clientDataJSON":"`)
	us.Contains(gotBody, `"clientExtensionResults":{}`)
	us.Contains(gotBody, `"transports":["usb"]`)
	us.Contains(gotBody, `"type":"public-key"`)

	// Results should be something like this
	//    {
	//            'id' => 'abcdefghABCDEFG',
	//            'rawId' => 'abcdefghABCDEFG',
	//            'response' => {
	//                'attestationObject' => 'pGNmbXRoZm...QbtEmc',
	//                'authenticatorData' => 'hgW4ugjCDUL55F...u0SZw',
	//                'clientDataJSON' => 'eyJ0eXBl...VsbH0=',
	//            },
	//            'transports' => ['usb'],
	//            'type' => 'public-key',
	//     };
}
