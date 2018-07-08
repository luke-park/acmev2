// Package protocol exposes the types and requests required to interact with an
// ACME v2 server.
package protocol

import "time"

// Directory represents a listing of the values in an ACME v2 directory.  The
// meta field is intentionally missing.
type Directory struct {
	KeyChange  string `json:"keyChange"`
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
}

// Account represents an ACME account.
type Account struct {
	Status       string   `json:"status"`
	Contact      []string `json:"contact"`
	TOSAgreed    bool     `json:"termsOfServiceAgreed"`
	OrderListURL string   `json:"orders"`
}

// AccountRequest represents a request payload for creating an account.
// Here, contacts is omitted intentionally.
type AccountRequest struct {
	TOSAgreed bool `json:"termsOfServiceAgreed"`
}

// OrderList represents a list of orders placed by a given account.
type OrderList struct {
	OrderURLs []string `json:"orders"`
}

// Order represents a single order.  URL is not returned in the object and not
// guaranteed to be populated.
type Order struct {
	URL string

	Status            string       `json:"status"`
	Expires           time.Time    `json:"expires,omitempty"`
	Identifiers       []Identifier `json:"identifiers"`
	NotBefore         time.Time    `json:"notBefore,omitempty"`
	NotAfter          time.Time    `json:"notAfter,omitempty"`
	Error             ErrorObject  `json:"error,omitempty"`
	AuthorizationURLs []string     `json:"authorizations"`
	FinalizeURL       string       `json:"finalize"`
	CertificateURL    string       `json:"certificate,omitempty"`
}

// OrderRequest represents a request payload for creating a new order.
// notBefore and notAfter are intentionally not implemented.
type OrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
}

// Authorization represents a authorization for a single identifier.
type Authorization struct {
	Identifier Identifier  `json:"identifier"`
	Status     string      `json:"status"`
	Expires    time.Time   `json:"expires,omitempty"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard,omitempty"`
}

// Identifier represents a single identifier object.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Challenge represents a single challenge object.  The first set of fields are
// possible for all challenges.  The following sets of fields are only present
// in certain types of requests, as per the ACME spec.  Currently, this only
// pertains to the Token field.
type Challenge struct {
	Type      string      `json:"type"`
	URL       string      `json:"url"`
	Status    string      `json:"status"`
	Validated time.Time   `json:"validated,omitempty"`
	Error     ErrorObject `json:"error,omitempty"`

	Token string `json:"token,omitempty"`
}

// FinalizeRequest represents the payload sent to finalize an order.
type FinalizeRequest struct {
	CSR string `json:"csr"`
}

// ErrorObject represents a response from an ACME v2 server for an error
// condition.  This struct should be used to unmarshal JSON from HTTP responses
// with status codes >= 400.
type ErrorObject struct {
	Type        string        `json:"type"`
	Detail      string        `json:"detail"`
	Subproblems []ErrorObject `json:"subproblems,omitempty"`
}

// The following const declarations are possible values for the status parameter
// that is included in a number of different ACME objects.
const (
	StatusReady       = "ready"
	StatusPending     = "pending"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"
)

// The following const declarations are possible values for challenge types.
// tls-alpn-01 is listed here since it can be returned by Let's Encrypt, but
// it is not supported directly in this implementation.
const (
	ChallengeTypeDNS01     = "dns-01"
	ChallengeTypeHTTP01    = "http-01"
	ChallengeTypeTLSALPN01 = "tls-alpn-01"
)

// The following const declarations are for possible error values retErrored in
// the "Type" parameter of an ErrorResponse.
const (
	ErrorAccountDoesNotExist     = "urn:ietf:params:acme:error:accountDoesNotExist"
	ErrorBadCSR                  = "urn:ietf:params:acme:error:badCSR"
	ErrorBadNonce                = "urn:ietf:params:acme:error:badNonce"
	ErrorBadRevocationReason     = "urn:ietf:params:acme:error:badRevocationReason"
	ErrorBadSignatureAlgorithm   = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ErrorCAA                     = "urn:ietf:params:acme:error:caa"
	ErrorCompound                = "urn:ietf:params:acme:error:compound"
	ErrorConnection              = "urn:ietf:params:acme:error:connection"
	ErrorDNS                     = "urn:ietf:params:acme:error:dns"
	ErrorExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired"
	ErrorIncorrectResponse       = "urn:ietf:params:acme:error:incorrectResponse"
	ErrorInvalidContact          = "urn:ietf:params:acme:error:invalidContact"
	ErrorMalformed               = "urn:ietf:params:acme:error:malformed"
	ErrorRateLimited             = "urn:ietf:params:acme:error:ratelimited"
	ErrorRejectedIdentifier      = "urn:ietf:params:acme:error:rejectedIdentifier"
	ErrorServerInternal          = "urn:ietf:params:acme:error:serverInternal"
	ErrorTLS                     = "urn:ietf:params:acme:error:tls"
	ErrorUnauthorized            = "urn:ietf:params:acme:error:unauthorized"
	ErrorUnsupportedContact      = "urn:ietf:params:acme:error:unsupportedContact"
	ErrorUnsupportedIdentifier   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ErrorUserActionRequired      = "urn:ietf:params:acme:error:userActionRequired"
)

// RequestMIMEType is the MIME type used for POST requests to ACME servers.
const RequestMIMEType = "application/jose+json"

// DNSIdentifierCollection returns a []Identifier for the provided DNS names.
func DNSIdentifierCollection(dnsNames ...string) []Identifier {
	r := make([]Identifier, len(dnsNames))

	for i, v := range dnsNames {
		r[i] = Identifier{Type: "dns", Value: v}
	}

	return r
}
