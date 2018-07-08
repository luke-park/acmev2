package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestECDSA(t *testing.T) {
	prv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	buf := &bytes.Buffer{}
	err = EncodeKey(prv1, buf)
	if err != nil {
		t.Error(err)
	}

	prv2, err := DecodeECDSAKey(buf)
	if err != nil {
		t.Error(err)
	}

	if prv1.D.Cmp(prv2.D) != 0 {
		t.Errorf("Expected: %v\nGot: %v\n", prv1.D, prv2.D)
	}
}

func TestRSA(t *testing.T) {
	prv1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	buf := &bytes.Buffer{}
	err = EncodeKey(prv1, buf)
	if err != nil {
		t.Error(err)
	}

	prv2, err := DecodeRSAKey(buf)
	if err != nil {
		t.Error(err)
	}

	if prv1.D.Cmp(prv2.D) != 0 {
		t.Errorf("Expected: %v\nGot: %v\n", prv1.D, prv2.D)
	}
}
