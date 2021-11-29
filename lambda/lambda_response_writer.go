package main

import "net/http"

type lambdaResponseWriter struct {
	Body    []byte
	Headers http.Header
	Status  int
}

func newLambdaResponseWriter() lambdaResponseWriter {
	w := lambdaResponseWriter{}
	w.Headers = http.Header{}
	return w
}

func (l lambdaResponseWriter) Header() http.Header {
	return l.Headers
}

func (l lambdaResponseWriter) Write(contents []byte) (int, error) {
	// If WriteHeader has not been called, Write is supposed to set default status code
	if l.Status == 0 {
		l.Status = http.StatusOK
	}

	l.Body = append(l.Body, contents...)
	return len(l.Body), nil
}

func (l lambdaResponseWriter) WriteHeader(statusCode int) {
	l.Status = statusCode
}
