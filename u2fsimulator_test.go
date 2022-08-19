package mfa

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func (ms *MfaSuite) Test_U2fRegistration() {

	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"

	rpID := "http://ourTestApp"

	httpWriter := newLambdaResponseWriter()
	requestBody, err := json.Marshal(map[string]string{
		"challenge": challenge,
	})
	ms.NoError(err, "error just creating body params for test")

	httpRequest, err := http.NewRequest(http.MethodPost, "https://example.com", bytes.NewBuffer(requestBody))
	ms.NoError(err, "error just creating http request for test")

	httpRequest.Header.Set("x-mfa-UserUUID", "the-id-of-the-dynamo-user")
	httpRequest.Header.Set("x-mfa-RPID", rpID)
	httpRequest.Header.Set("x-mfa-RPOrigin", rpID)

	U2fRegistration(httpWriter, httpRequest)

	gotBody := string(httpWriter.Body)
	ms.Contains(gotBody, `"id":"`)
	ms.Contains(gotBody, `"rawId":"`)
	ms.Contains(gotBody, `"response":{"authenticatorData":"`)
	ms.Contains(gotBody, `"attestationObject":"`)
	ms.Contains(gotBody, `"clientDataJSON":"`)
	ms.Contains(gotBody, `"clientExtensionResults":{}`)
	ms.Contains(gotBody, `"transports":["usb"]`)
	ms.Contains(gotBody, `"type":"public-key"`)

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
