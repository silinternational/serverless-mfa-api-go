package models

import "errors"

var (
	ErrEmptySecret        = errors.New("empty secret cannot be hashed")
	ErrEmptyCompareSecret = errors.New("secret to compare cannot be empty")
	ErrEmptyHashedSecret  = errors.New("cannot compare with empty hashed secret")
	ErrInvalidLegacyData  = errors.New("ciphertext contains more than one colon, does not look like legacy data")

	ErrUserNotExist    = errors.New("user does not exist")
	ErrNoUserInContext = errors.New("unable to get user from request context")

	ErrMissingRequiredHeader = errors.New("missing required header")
)
