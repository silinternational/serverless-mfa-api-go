package main

import "net/http"

type lambdaResponseWriter struct {
	Body    []byte
	Headers http.Header
	Status  int
}

func (l lambdaResponseWriter) initHeader() {
	if l.Headers == nil {
		l.Headers = http.Header{}
	}
}

func (l lambdaResponseWriter) Header() http.Header {
	l.initHeader()
	return l.Headers
}

func (l lambdaResponseWriter) Write(contents []byte) (int, error) {
	l.initHeader()
	// If WriteHeader has not been called, Write is supposed to set default status code
	if l.Status == 0 {
		l.Status = http.StatusOK
	}

	l.Body = append(l.Body, contents...)
	return len(l.Body), nil
}

func (l lambdaResponseWriter) WriteHeader(statusCode int) {
	l.initHeader()
	l.Status = statusCode
}
