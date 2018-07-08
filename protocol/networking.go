package protocol

import (
	"bytes"
	"crypto"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/luke-park/acmev2/crypto/jwk"
	"github.com/luke-park/acmev2/crypto/jws"
)

// GetDirectory returns an ACME directory for the given directory URL.
func GetDirectory(url string) (*Directory, error) {
	if url == "" {
		return nil, ErrArgumentInvalid
	}

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, BuildHTTPError(res)
	}

	directory := &Directory{}
	if err := decodeReader(directory, res.Body); err != nil {
		return nil, err
	}

	return directory, nil
}

// GetNonce returns a new nonce using the provided directory.
func GetNonce(directory *Directory) (string, error) {
	if directory == nil {
		return "", ErrArgumentInvalid
	}

	res, err := http.Head(directory.NewNonce)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return "", BuildHTTPError(res)
	}

	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", ErrNonceExpected
	}

	return nonce, nil
}

// GetKeyIDForKey returns an existing account for the provided key, or, if one
// does not exist, creates an account for the provided key.  The first return
// value is the KeyID for the account, and the second is a new nonce.
func GetKeyIDForKey(directory *Directory, nonce string, key crypto.PrivateKey) (string, string, error) {
	if directory == nil || nonce == "" || key == nil {
		return "", "", ErrArgumentInvalid
	}

	payload := &AccountRequest{TOSAgreed: true}
	body, err := encodeToJWS(payload, key, "", nonce, directory.NewAccount)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest(http.MethodPost, directory.NewAccount, body)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", RequestMIMEType)

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	nonce = res.Header.Get("Replay-Nonce")

	if _, err := CheckResponseForErrors(res); err != nil {
		return "", "", err
	}

	keyID := res.Header.Get("Location")
	if keyID == "" {
		return "", "", ErrKeyIDEmpty
	}

	return keyID, nonce, nil
}

// GetAccount returns an *Account, and new nonce, for the provided KeyID.
func GetAccount(nonce string, key crypto.PrivateKey, keyID string) (*Account, string, error) {
	if nonce == "" || key == nil || keyID == "" {
		return nil, "", ErrArgumentInvalid
	}

	payload := &struct{}{}
	body, err := encodeToJWS(payload, key, keyID, nonce, keyID)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequest(http.MethodPost, keyID, body)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", RequestMIMEType)

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()

	nonce = res.Header.Get("Replay-Nonce")

	if _, err := CheckResponseForErrors(res); err != nil {
		return nil, "", err
	}

	account := &Account{}
	err = decodeReader(account, res.Body)
	if err != nil {
		return nil, "", err
	}

	return account, nonce, nil
}

// CreateOrder creates a new order for the collection of identifiers provided.
// It returns an *Order and a new nonce.
func CreateOrder(directory *Directory, nonce string, key crypto.PrivateKey, keyID string, identifiers ...Identifier) (*Order, string, error) {
	if directory == nil || nonce == "" || key == nil || keyID == "" || identifiers == nil {
		return nil, "", ErrArgumentInvalid
	}

	payload := &OrderRequest{Identifiers: identifiers}
	body, err := encodeToJWS(payload, key, keyID, nonce, directory.NewOrder)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequest(http.MethodPost, directory.NewOrder, body)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", RequestMIMEType)

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()

	nonce = res.Header.Get("Replay-Nonce")

	if _, err := CheckResponseForErrors(res); err != nil {
		return nil, "", err
	}

	order := &Order{}
	err = decodeReader(order, res.Body)
	if err != nil {
		return nil, "", err
	}

	order.URL = res.Header.Get("Location")

	return order, nonce, nil
}

// GetOrder retrieves the Order at the provided URL.
func GetOrder(url string) (*Order, error) {
	if url == "" {
		return nil, ErrArgumentInvalid
	}

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if _, err := CheckResponseForErrors(res); err != nil {
		return nil, err
	}

	order := &Order{}
	err = decodeReader(order, res.Body)
	if err != nil {
		return nil, err
	}

	return order, nil
}

// GetAuthorization retrieves the authorization at the provided URL.
func GetAuthorization(url string) (*Authorization, error) {
	if url == "" {
		return nil, ErrArgumentInvalid
	}

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if _, err := CheckResponseForErrors(res); err != nil {
		return nil, err
	}

	authorization := &Authorization{}
	err = decodeReader(authorization, res.Body)
	if err != nil {
		return nil, err
	}

	return authorization, nil
}

// GetChallenge retrieves the challenge at the provided URL.
func GetChallenge(url string) (*Challenge, error) {
	if url == "" {
		return nil, ErrArgumentInvalid
	}

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if _, err := CheckResponseForErrors(res); err != nil {
		return nil, err
	}

	challenge := &Challenge{}
	err = decodeReader(challenge, res.Body)
	if err != nil {
		return nil, err
	}

	return challenge, nil
}

// NotifyChallengeComplete sends an empty POST request to the server to notify
// that the client has completed the challenge.
func NotifyChallengeComplete(url string, nonce string, key crypto.PrivateKey, keyID string) (string, error) {
	if url == "" || nonce == "" || key == nil || keyID == "" {
		return "", ErrArgumentInvalid
	}

	payload := &struct{}{}
	body, err := encodeToJWS(payload, key, keyID, nonce, url)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", RequestMIMEType)

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	nonce = res.Header.Get("Replay-Nonce")

	if _, err := CheckResponseForErrors(res); err != nil {
		return "", err
	}

	return nonce, nil
}

// FinalizeOrder submits a CSR to the server to finalize an order.  It should
// only be called when each challenge used has been verified as valid.
func FinalizeOrder(order *Order, csr string, nonce string, key crypto.PrivateKey, keyID string) (string, error) {
	if order == nil || csr == "" || nonce == "" || key == nil || keyID == "" {
		return "", ErrArgumentInvalid
	}

	payload := &FinalizeRequest{CSR: csr}
	body, err := encodeToJWS(payload, key, keyID, nonce, order.FinalizeURL)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, order.FinalizeURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", RequestMIMEType)

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	nonce = res.Header.Get("Replay-Nonce")

	if _, err := CheckResponseForErrors(res); err != nil {
		return "", err
	}

	return nonce, nil
}

// GetCertificate takes an *Order and retrieves the certificate that has been
// created for that order, if it exists.  The resulting []byte is a series of
// one or more PEM-encoded X509 certificates.
func GetCertificate(order *Order) ([]byte, error) {
	if order == nil {
		return nil, ErrArgumentInvalid
	}

	res, err := http.Get(order.CertificateURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if _, err := CheckResponseForErrors(res); err != nil {
		return nil, err
	}

	return ioutil.ReadAll(res.Body)
}

// decodeReader is a helper-function that JSON decodes the provided io.Reader
// into "inst".
func decodeReader(inst interface{}, r io.Reader) error {
	d := json.NewDecoder(r)
	err := d.Decode(inst)
	if err != nil {
		return err
	}

	return nil
}

// encodeToJWS takes a payload object and a URL and builds a JWS object into a
// buffer that can be used as a request body in an HTTP request.
func encodeToJWS(payload interface{}, key crypto.PrivateKey, keyID string, nonce string, url string) (*bytes.Buffer, error) {
	if payload == nil || nonce == "" || url == "" || key == nil {
		return nil, ErrArgumentInvalid
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	var k *jwk.Key
	if keyID == "" {
		k, err = jwk.ToJWK(key)
		if err != nil {
			return nil, err
		}
	}

	alg, err := jws.DetermineAlgorithm(key)
	if err != nil {
		return nil, err
	}

	header := jws.ConstructHeader(k, keyID, alg, nonce, url)
	obj, err := jws.ConstructObject(header, raw, key)
	if err != nil {
		return nil, err
	}

	str, err := obj.ToJSON()
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer([]byte(str)), nil
}
