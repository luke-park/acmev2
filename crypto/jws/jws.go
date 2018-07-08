// Package jws exposes functionality for working with JSON Web Signatures.
// This package is not a complete JWS implementation, only the required
// portions of RFC7515 are implemented.
package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"

	acmecrypto "github.com/luke-park/acmev2/crypto"
	"github.com/luke-park/acmev2/crypto/jwk"
)

// Header represents a JWS object header.  It is best to not construct an
// instance of Header manually.  Prefer ConstructHeader.
type Header struct {
	Algorithm string   `json:"alg"`
	Key       *jwk.Key `json:"jwk,omitempty"`
	KeyID     string   `json:"kid,omitempty"`
	Nonce     string   `json:"nonce"`
	URL       string   `json:"url"`
}

// Object represents a JWS object.  It is best to not construct an instance of
// Object manually.  Prefer ConstructObject.
type Object struct {
	Header    string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// ToJSON converts the given Object instance to JSON.  This is not implemented
// as String() as JSON marshalling can return an error.
func (o *Object) ToJSON() (string, error) {
	raw, err := json.Marshal(o)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}

// ConstructHeader builds a Header instance from the given information.
// If key is nil, KeyID in the resulting instance is set to the argument
// provided to ConstructHeader.  Otherwise, Key is set accordingly.
func ConstructHeader(key *jwk.Key, keyID, algorithm, nonce, url string) *Header {
	header := &Header{}

	header.Key = key
	if header.Key == nil {
		header.KeyID = keyID
	}

	header.Algorithm = algorithm
	header.Nonce = nonce
	header.URL = url

	return header
}

// ConstructObject builds a JWS object using the given parameters.  Here,
// payload is a JSON byte slice.  The signature for the object is computed using
// the provided key, which is expected to be either a *ecdsa.PrivateKey or a
// *rsa.PrivateKey.
func ConstructObject(header *Header, payload []byte, key crypto.PrivateKey) (*Object, error) {
	algo, err := DetermineAlgorithm(key)
	if err != nil {
		return nil, err
	}

	hash, err := GetHashForAlgorithm(algo)
	if err != nil {
		return nil, err
	}

	headerRaw, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerRaw)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	hash.Write([]byte(headerB64 + "." + payloadB64))

	signature, err := ProduceSignature(key, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	return &Object{headerB64, payloadB64, base64.RawURLEncoding.EncodeToString(signature)}, nil
}

// ProduceSignature takes a key of type *ecdsa.PrivateKey or *rsa.PrivateKey
// and a piece of data and signs it with the given key.
func ProduceSignature(prv crypto.PrivateKey, data []byte) ([]byte, error) {
	switch k := prv.(type) {
	case *ecdsa.PrivateKey:
		b1, b2, err := ecdsa.Sign(rand.Reader, k, data)
		if err != nil {
			return nil, err
		}

		rr := b1.Bytes()
		sr := b2.Bytes()
		s := (k.Params().BitSize + 7) / 8
		r := make([]byte, s*2)
		copy(r[s-len(rr):], rr)
		copy(r[s*2-len(sr):], sr)

		return r, nil
	case *rsa.PrivateKey:
		return k.Sign(rand.Reader, data, nil)
	}

	return nil, acmecrypto.ErrKeyFormat
}

// DetermineAlgorithm takes a given crypto.PrivateKey and returns the
// appropriate string identifier e.g. ES256, ES384 or RS256.  The provided key
// should be of type *ecdsa.PrivateKey or *rsa.PrivateKey.
func DetermineAlgorithm(key crypto.PrivateKey) (string, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Params().BitSize == 256 {
			return "ES256", nil
		}
		if k.Params().BitSize == 384 {
			return "ES384", nil
		}

		return "", acmecrypto.ErrKeyFormat
	case *rsa.PrivateKey:
		return "RS256", nil
	}

	return "", acmecrypto.ErrKeyFormat
}

// GetHashForAlgorithm takes a string input representing the identifier of the
// algorithm e.g. ES256, ES384 or RS256 and returns the hash.Hash that should
// be used with the given algorithm.
func GetHashForAlgorithm(algo string) (hash.Hash, error) {
	switch strings.ToUpper(algo) {
	case "ES256":
		fallthrough
	case "RS256":
		return sha256.New(), nil
	case "ES384":
		return sha512.New384(), nil
	}

	return nil, acmecrypto.ErrUnknownAlgorithm
}
