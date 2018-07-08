package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestDetermineAlgorithm(t *testing.T) {
	e256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	e384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	algE256, err := DetermineAlgorithm(e256)
	if err != nil {
		t.Error(err)
	}

	algE384, err := DetermineAlgorithm(e384)
	if err != nil {
		t.Error(err)
	}

	algRSA, err := DetermineAlgorithm(rsaKey)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(algE256, "ES256") != 0 {
		t.Errorf("Got: %v\nExpected: %v\n", algE256, "ES256")
	}

	if strings.Compare(algE384, "ES384") != 0 {
		t.Errorf("Got: %v\nExpected: %v\n", algE384, "ES384")
	}

	if strings.Compare(algRSA, "RS256") != 0 {
		t.Errorf("Got: %v\nExpected: %v\n", algRSA, "RS256")
	}
}
