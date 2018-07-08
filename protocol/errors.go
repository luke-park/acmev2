package protocol

import (
	"errors"
	"fmt"
	"net/http"
)

// The following collection of variables represents a number of errors that can
// be returned by the functions and methods in this package.
var (
	ErrArgumentInvalid = errors.New("required argument was nil or empty")
	ErrTOSChanged      = errors.New("provider TOS have changed")
	ErrNonceExpected   = errors.New("value of the Replay-Nonce header was missing or empty")
	ErrKeyIDEmpty      = errors.New("the provided, or returned, keyID was empty")
	ErrBadStatus       = errors.New("the returned status indicates a failed request - perhaps start again")
)

// BuildHTTPError constructs an error for the given *http.Response.
func BuildHTTPError(res *http.Response) error {
	return fmt.Errorf("HTTP Response Code %v: %v", res.StatusCode, res.Status)
}

// BuildACMEError constructs an error from the provided *ErrorObject.
func BuildACMEError(res *ErrorObject) error {
	return fmt.Errorf("ACME Error Response %v: %v", res.Type, res.Detail)
}

// CheckResponseForErrors checks the provided *http.Response for errors and
// returns an *ErrorObject and an error.  Only if both are nil should the
// response be considered error-free.  Values for the error should be processed
// BEFORE the *ErrorObject.
func CheckResponseForErrors(res *http.Response) (*ErrorObject, error) {
	if res.StatusCode < 400 {
		return nil, nil
	}

	errObj := &ErrorObject{}
	if err := decodeReader(errObj, res.Body); err != nil {
		return nil, BuildHTTPError(res)
	}

	if errObj.Type == "" {
		return nil, BuildHTTPError(res)
	}

	if errObj.Type == ErrorUserActionRequired {
		return errObj, ErrTOSChanged
	}

	return errObj, BuildACMEError(errObj)
}
