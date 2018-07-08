package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

const (
	TestECDSAX string = "JOSibDbMO3aQcuCmU2F4Fedf1yAazCXz6zDQaaDjsGQ"
	TestECDSAY string = "ZYbsUdLhek5zQSisq99yogqpKng_3QQHM4Ptg9Z4gow"
	TestRSAE   string = "AQAB"
	TestRSAN   string = "m8uca9FieUkLllZTgu4pBLUG0K4y9ancC9MPqleZQQL7sREYWuS" +
		"lnQ604LJ5-WXCqH_ZuWgo3thop189xDqNrqJA7eNbbD4FNaOfar" +
		"Hbh6ZLqbg08iiZ493qze5M7ne427I2rkafxcxc6wlsLXJaqbXGA" +
		"haA8swymmliIffDwk5KzXfUjoSgSjlMu-2-mI0xpKaCriIpS-Un" +
		"NEWmiCvGyTjJ4gL78HY8WS_4SGGEcOB4inySXngRVKBLrenHcNO" +
		"_-vjGZQoODLXTFtoF0--UqTCd2ATgT8ebPgUHXb6BMmass2UUzk" +
		"Fw0YA_E5gXTwlcjUm-IQFWktlMbq6JqkS7sw"
)

func TestECDSA(t *testing.T) {
	xr, err := base64.RawURLEncoding.DecodeString(TestECDSAX)
	if err != nil {
		t.Error(err)
	}

	yr, err := base64.RawURLEncoding.DecodeString(TestECDSAY)
	if err != nil {
		t.Error(err)
	}

	x := big.NewInt(0).SetBytes(xr)
	y := big.NewInt(0).SetBytes(yr)

	k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	jwk, err := ToJWK(k)
	if err != nil {
		t.Error(err)
	}

	json, err := jwk.ToJSON()
	if err != nil {
		t.Error(err)
	}

	jsonCmp := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%v","y":"%v"}`, TestECDSAX, TestECDSAY)
	if strings.Compare(json, jsonCmp) != 0 {
		t.Errorf("Expected: %v\nGot: %v\n", jsonCmp, json)
	}
}

func TestRSA(t *testing.T) {
	er, err := base64.RawURLEncoding.DecodeString(TestRSAE)
	if err != nil {
		t.Error(err)
	}

	nr, err := base64.RawURLEncoding.DecodeString(TestRSAN)
	if err != nil {
		t.Error(err)
	}

	e := int(big.NewInt(0).SetBytes(er).Int64())
	n := big.NewInt(0).SetBytes(nr)

	k := &rsa.PublicKey{N: n, E: e}

	jwk, err := ToJWK(k)
	if err != nil {
		t.Error(err)
	}

	json, err := jwk.ToJSON()
	if err != nil {
		t.Error(err)
	}

	jsonCmp := fmt.Sprintf(`{"e":"%v","kty":"RSA","n":"%v"}`, TestRSAE, TestRSAN)
	if strings.Compare(json, jsonCmp) != 0 {
		t.Errorf("Expected: %v\nGot: %v\n", jsonCmp, json)
	}
}
