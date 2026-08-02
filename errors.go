package auth

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrInvalidConfiguration = errors.New("invalid authentication configuration")
	ErrAuthentication       = errors.New("authentication failed")
	ErrAuthorization        = errors.New("authorization failed")
	ErrSessionNotFound      = errors.New("session not found")
	ErrInvalidState         = errors.New("invalid OAuth state")
	ErrInvalidNonce         = errors.New("invalid OIDC nonce")
	ErrMissingCode          = errors.New("authorization code is missing")
	ErrMissingIDToken       = errors.New("ID token is missing")
	ErrMissingRefreshToken  = errors.New("refresh token is missing")
	ErrTokenRefresh         = errors.New("token refresh failed")
	ErrInsufficientRole     = errors.New("insufficient role")
)

// Error is an error returned by the auth package.
//
// Code is stable enough for callers to inspect with errors.As.
// Err supports errors.Is through Unwrap.
type Error struct {
	Operation string
	Code      string
	Message   string
	Err       error
}

func (e *Error) Error() string {
	switch {
	case e.Operation != "" && e.Message != "":
		return fmt.Sprintf("%s: %s", e.Operation, e.Message)
	case e.Operation != "":
		return e.Operation
	case e.Message != "":
		return e.Message
	case e.Err != nil:
		return e.Err.Error()
	default:
		return "authentication error"
	}
}

func (e *Error) Unwrap() error {
	return e.Err
}

func wrapError(
	operation string,
	code string,
	message string,
	err error,
) error {
	return &Error{
		Operation: operation,
		Code:      code,
		Message:   message,
		Err:       err,
	}
}

// ErrorHandler translates package errors into HTTP responses.
//
// Applications can replace this function through Config.ErrorHandler.
type ErrorHandler func(
	w http.ResponseWriter,
	r *http.Request,
	err error,
)

func DefaultErrorHandler(
	w http.ResponseWriter,
	_ *http.Request,
	err error,
) {
	status := http.StatusInternalServerError
	message := "internal authentication error"

	switch {
	case errors.Is(err, ErrInvalidState),
		errors.Is(err, ErrMissingCode):

		status = http.StatusBadRequest
		message = "invalid authentication request"

	case errors.Is(err, ErrSessionNotFound),
		errors.Is(err, ErrAuthentication),
		errors.Is(err, ErrInvalidNonce),
		errors.Is(err, ErrMissingIDToken),
		errors.Is(err, ErrMissingRefreshToken),
		errors.Is(err, ErrTokenRefresh):

		status = http.StatusUnauthorized
		message = "authentication required"

	case errors.Is(err, ErrInsufficientRole),
		errors.Is(err, ErrAuthorization):

		status = http.StatusForbidden
		message = "access denied"

	case errors.Is(err, ErrInvalidConfiguration):
		status = http.StatusInternalServerError
		message = "authentication is not configured correctly"
	}

	http.Error(w, message, status)
}
