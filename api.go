package mfa

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const IDParam = "id"

// simpleError is a custom error type that can be JSON-encoded for API responses
type simpleError struct {
	Error string `json:"error"`
}

// newSimpleError creates a new simpleError from the given error
func newSimpleError(err error) simpleError {
	return simpleError{Error: err.Error()}
}

// invalidRequest is a helper for response to an invalid request, such as when the request body cannot be decoded
func invalidRequest(w http.ResponseWriter, err error) {
	jsonResponse(w, fmt.Errorf("invalid request: %s", err), http.StatusBadRequest)
}

// getStorageClient retrieves a Storage client from the request context
func getStorageClient(r *http.Request) (*Storage, error) {
	storage, ok := r.Context().Value(StorageContextKey).(*Storage)
	if !ok {
		return nil, fmt.Errorf("no storage client found in context")
	}
	return storage, nil
}

// jsonResponse encodes a body as JSON and writes it to the response. It sets the response Content-Type header to
// "application/json".
func jsonResponse(w http.ResponseWriter, body interface{}, status int) {
	var data interface{}
	switch b := body.(type) {
	case error:
		data = newSimpleError(b)
	default:
		data = body
	}

	var jBody []byte
	var err error
	if data != nil {
		jBody, err = json.Marshal(data)
		if err != nil {
			log.Printf("failed to marshal response body to json: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to marshal response body to json"))
			return
		}
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(jBody)
	if err != nil {
		log.Printf("failed to write response in jsonResponse: %s\n", err)
	}
}
