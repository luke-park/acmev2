package acmev2

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"acmev2/crypto/jwk"
	"acmev2/protocol"
)

// Client facilitates interaction with an ACME v2 server.  It handles all direct
// communication and automates nonce handling, keys, key authorizations etc.
//
// In nearly all instances, Client should only ever be instantiated using the
// NewClient function.
type Client struct {
	Key           crypto.PrivateKey
	KeyID         string
	KeyThumbprint string

	UsableNonce string
	Directory   *protocol.Directory
}

// The following collection of variables represents a number of errors that can
// be returned by the functions and methods in this package.
var (
	ErrNilKey     = errors.New("provided key is nil")
	ErrThumbprint = errors.New("thumbprint was missing or invalid")
)

// NewClient builds a new instance of Client from the provided information.
// Note that this function makes up to 3 network requests before it returns.
func NewClient(providerURL string, key crypto.PrivateKey) (*Client, error) {
	if key == nil {
		return nil, ErrNilKey
	}

	thumbprint, err := computeThumbprint(key)
	if err != nil {
		return nil, err
	}

	c := &Client{
		Key:           key,
		KeyThumbprint: thumbprint,
	}

	c.Directory, err = protocol.GetDirectory(providerURL)
	if err != nil {
		return nil, err
	}

	c.UsableNonce, err = protocol.GetNonce(c.Directory)
	if err != nil {
		return nil, err
	}

	c.KeyID, c.UsableNonce, err = protocol.GetKeyIDForKey(c.Directory, c.UsableNonce, c.Key)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// PlaceOrder requests creation of a new order for the given identifiers.
// It returns an *protocol.Order.
func (c *Client) PlaceOrder(identifiers ...protocol.Identifier) (*protocol.Order, error) {
	var err error
	if c.UsableNonce == "" {
		c.UsableNonce, err = protocol.GetNonce(c.Directory)
		if err != nil {
			return nil, err
		}
	}

	var order *protocol.Order
	order, c.UsableNonce, err = protocol.CreateOrder(c.Directory, c.UsableNonce, c.Key, c.KeyID, identifiers...)
	if err != nil {
		return nil, err
	}

	return order, nil
}

// GetOrder returns a *protocol.Order from the provided URL.
func (c *Client) GetOrder(url string) (*protocol.Order, error) {
	return protocol.GetOrder(url)
}

// GetAuthorizations returns a slice of *protocol.Authorization from the
// provided *protocol.Order.
func (c *Client) GetAuthorizations(order *protocol.Order) ([]*protocol.Authorization, error) {
	r := make([]*protocol.Authorization, len(order.AuthorizationURLs))

	for i, v := range order.AuthorizationURLs {
		auth, err := protocol.GetAuthorization(v)
		if err != nil {
			return nil, err
		}

		r[i] = auth
	}

	return r, nil
}

// GetChallenge returns a *protocol.Challenge from the provided URL.
func (c *Client) GetChallenge(url string) (*protocol.Challenge, error) {
	return protocol.GetChallenge(url)
}

// MarkComplete takes a *protocol.Challenge and alerts the server that the
// challenge has been completed.
func (c *Client) MarkComplete(challenge *protocol.Challenge) error {
	var err error
	if c.UsableNonce == "" {
		c.UsableNonce, err = protocol.GetNonce(c.Directory)
		if err != nil {
			return err
		}
	}

	c.UsableNonce, err = protocol.NotifyChallengeComplete(challenge.URL, c.UsableNonce, c.Key, c.KeyID)
	return err
}

// FinalizeOrder takes a *protocol.Order and a base64 URL encoded DER #PKCS10
// CSR and uses them to finalize an order with the server.  Only call this
// method if all the auths in the order have had one of their challenges
// completed and checked to be valid.s
func (c *Client) FinalizeOrder(order *protocol.Order, csr string) error {
	var err error
	if c.UsableNonce == "" {
		c.UsableNonce, err = protocol.GetNonce(c.Directory)
		if err != nil {
			return err
		}
	}

	c.UsableNonce, err = protocol.FinalizeOrder(order, csr, c.UsableNonce, c.Key, c.KeyID)
	return err
}

// GetCertificate takes an *Order and retrieves the certificate that has been
// created for that order, if it exists.  The resulting []byte is a series of
// one or more PEM-encoded X509 certificates.
func (c *Client) GetCertificate(order *protocol.Order) ([]byte, error) {
	return protocol.GetCertificate(order)
}

// ComputeKeyAuthorizationDigest returns the Key Authorization Digest for
// the provided token using the key associated with the client.  The result of
// this call is the value to be returned in HTTP and DNS challenges.
func (c *Client) ComputeKeyAuthorizationDigest(token string) (string, error) {
	if c.KeyThumbprint == "" {
		return "", ErrThumbprint
	}

	hash := sha256.Sum256([]byte(token + "." + c.KeyThumbprint))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// computeThumbprint returns the JWK thumbprint, as defined in RFC7638, for
// the provided key.
func computeThumbprint(key crypto.PrivateKey) (string, error) {
	jk, err := jwk.ToJWK(key)
	if err != nil {
		return "", err
	}

	str, err := jk.ToJSON()
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(str))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
