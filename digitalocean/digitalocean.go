// Package digitalocean represents the portion of acmev2 that automatically
// updates DNS records for domains hosted with Digital Ocean.
//
// This package is designed with the pure intention of solving ACME challenges.
package digitalocean

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// DomainRecord represents a single domain record response from the Digital
// Ocean API.  The bottom set of records are encoded automatically as null.
type DomainRecord struct {
	ID   *int   `json:"id,omitempty"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`

	Priority *int    `json:"priority"`
	Port     *int    `json:"port"`
	Weight   *int    `json:"weight"`
	Flags    *int    `json:"flags"`
	Tag      *string `json:"tag"`
}

// DomainResponse represents the response from the Digital Ocean API when
// requesting DNS records.
type DomainResponse struct {
	Records []DomainRecord `json:"domain_records"`
}

// Client is a basic network client that handles DigitalOcean authentication and
// communication.
type Client struct {
	Token string
}

// A collection of Digital Ocean API Endpoints used by this package.
const (
	APIBase   = "https://api.digitalocean.com"
	APIList   = "/v2/domains/%v/records"
	APIDelete = "/v2/domains/%v/records/%v"
	APICreate = "/v2/domains/%v/records"
)

// The following collection of variables represents a number of errors that can
// be returned by the functions and methods in this package.
var (
	ErrArgumentInvalid = errors.New("required argument was nil or empty")
)

// NewClient creates a new Digital Ocean client with the provided token.
func NewClient(token string) *Client {
	return &Client{Token: token}
}

// ListRecords returns a listing of all DNS records for a given domain.
func (c *Client) ListRecords(domain string) ([]DomainRecord, error) {
	if domain == "" {
		return nil, ErrArgumentInvalid
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(APIBase+APIList, domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.Token))

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, BuildHTTPError(res)
	}

	dr := &DomainResponse{}
	err = decodeReader(dr, res.Body)
	if err != nil {
		return nil, err
	}

	return dr.Records, nil
}

// DeleteRecord deletes the record with the provided ID for the given domain.
func (c *Client) DeleteRecord(domain string, id int) error {
	if domain == "" {
		return ErrArgumentInvalid
	}

	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf(APIBase+APIDelete, domain, id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.Token))

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		return BuildHTTPError(res)
	}

	return nil
}

// CreateRecord creates a new TXT record with the given name and value.
func (c *Client) CreateRecord(domain, name, value string) error {
	if name == "" || value == "" {
		return ErrArgumentInvalid
	}

	record := &DomainRecord{
		Type: "TXT",
		Name: name,
		Data: value,
		TTL:  3600,
	}

	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(raw)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf(APIBase+APICreate, domain), buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.Token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%v", len(raw)))

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return BuildHTTPError(res)
	}

	return nil
}

// BuildHTTPError constructs an error for the given *http.Response.
func BuildHTTPError(res *http.Response) error {
	return fmt.Errorf("HTTP Response Code %v: %v", res.StatusCode, res.Status)
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
