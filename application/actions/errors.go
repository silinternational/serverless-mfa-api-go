package actions

import "errors"

var (
	errUnauthorized        = errors.New("unauthorized")
	errInternalServerError = errors.New("internal server error")
)
