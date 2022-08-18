package mfa

import (
	"net/http"
	"net/url"
)

func (ms *MfaSuite) Test_U2fRegistration() {

	const challenge = "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE"

	httpWriter := newLambdaResponseWriter()
	httpRequest := http.Request{
		PostForm: url.Values{
			"challenge":        []string{challenge},
			"relying_party_id": []string{"ourTestApp"},
		},
	}
	U2fRegistration(httpWriter, &httpRequest)

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
