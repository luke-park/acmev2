// Package crypto exposes basic helper functionality for storing and retrieving
// private keys in PEM format.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
)

// ECDSAPEMHeader is the PEM header required for ECDSA keys.
const ECDSAPEMHeader string = "EC PRIVATE KEY"

// RSAPEMHeader is the PEM header required for RSA keys.
const RSAPEMHeader string = "RSA PRIVATE KEY"

// ErrKeyFormat is the error returned if a provided key is not an ECDSA or RSA
// asymmetric key.  It can also be returned if the key is of an invalid bit
// size.
var ErrKeyFormat = errors.New("provided key was of an invalid type, or was of an invalid bit size")

// ErrNoPEMData is the error returned if the provided data source does not
// contain any PEM formatted data.
var ErrNoPEMData = errors.New("provided data source does not contain any PEM formatted data")

// ErrUnknownAlgorithm is the error returned when the provided algorithm
// string identifier is unknown.
var ErrUnknownAlgorithm = errors.New("provided algorithm string identifier is unknown")

// EncodeKey encodes the given crypto.PrivateKey to the provided io.Writer in
// PEM format.  The provided key must be either a *rsa.PrivateKey or
// *ecdsa.PrivateKey.
func EncodeKey(prv crypto.PrivateKey, w io.Writer) error {
	switch k := prv.(type) {
	case *ecdsa.PrivateKey:
		return encodeECDSA(k, w)
	case *rsa.PrivateKey:
		return encodeRSA(k, w)
	default:
		return ErrKeyFormat
	}
}

// This helper function encodes a *ecdsa.PrivateKey to the given writer in
// PEM format.
func encodeECDSA(k *ecdsa.PrivateKey, w io.Writer) error {
	raw, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}

	block := &pem.Block{Type: ECDSAPEMHeader, Headers: nil, Bytes: raw}
	return pem.Encode(w, block)
}

// This helper function encodes a *rsa.PrivateKey to the given writer in
// PEM format.
func encodeRSA(k *rsa.PrivateKey, w io.Writer) error {
	raw := x509.MarshalPKCS1PrivateKey(k)
	block := &pem.Block{Type: RSAPEMHeader, Headers: nil, Bytes: raw}
	return pem.Encode(w, block)
}

// DecodeECDSAKey decodes an *ecdsa.PrivateKey from the PEM data provided by
// the given io.Reader.
func DecodeECDSAKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, ErrNoPEMData
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// DecodeRSAKey decodes a *rsa.PrivateKey from the PEM data provided by the
// given io.Reader.
func DecodeRSAKey(r io.Reader) (*rsa.PrivateKey, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, ErrNoPEMData
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
