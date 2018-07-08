// Package jwk exposes functionality for transforming go-native keys into
// JWKs for use with the ACMEv2 protocol.  This is not a complete JWK
// implementation, only the required portions of RFC7517 are implemented.
package jwk

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"

	acmecrypto "github.com/luke-park/acmev2/crypto"
)

// Key represents the structure of a JWK JSON object.  The entries are
// ordered like so to facilitate thumbprint computation.
type Key struct {
	Curve   string `json:"crv,omitempty"`
	E       string `json:"e,omitempty"`
	KeyType string `json:"kty"`
	N       string `json:"n,omitempty"`
	X       string `json:"x,omitempty"`
	Y       string `json:"y,omitempty"`
}

// ToJSON converts the given Key instance to JSON.  This is not implemented as
// String() as JSON marshalling can return an error.
func (k *Key) ToJSON() (string, error) {
	raw, err := json.Marshal(k)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}

// ToJWK takes the given public or private key pointer and marshals it to a JWK.
func ToJWK(key interface{}) (*Key, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		key := k.Public().(*ecdsa.PublicKey)
		return buildJWKFromECDSA(key)
	case *ecdsa.PublicKey:
		return buildJWKFromECDSA(k)
	case *rsa.PrivateKey:
		key := k.Public().(*rsa.PublicKey)
		return buildJWKFromRSA(key)
	case *rsa.PublicKey:
		return buildJWKFromRSA(k)
	default:
		return nil, acmecrypto.ErrKeyFormat
	}
}

// This helper function builds a *Key from an *ecdsa.PublicKey.  We have to
// ensure the bit length of X and Y fits with the curves BitSize, so we pad if
// necessary.
func buildJWKFromECDSA(k *ecdsa.PublicKey) (*Key, error) {
	x := k.X.Bytes()
	y := k.Y.Bytes()
	size := (k.Curve.Params().BitSize + 7) / 8

	if len(x) < size {
		x = append(make([]byte, size-len(x)), x...)
	}
	if len(y) < size {
		y = append(make([]byte, size-len(y)), y...)
	}

	return &Key{
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(x),
		Y:       base64.RawURLEncoding.EncodeToString(y),
	}, nil
}

// This helper functions builds a *Key from an *rsa.PublicKey.
func buildJWKFromRSA(k *rsa.PublicKey) (*Key, error) {
	return &Key{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E:       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}, nil
}
