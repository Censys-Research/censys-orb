package greynoise

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

const (
	defaultBaseURL   = "https://api.greynoise.io/v2"
	defaultUserAgent = "greynoise-go-client"
	maxIPsPerBatch   = 1000
)

// Client represents a GreyNoise API client
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	userAgent  string
}

// ClientOption is a function that modifies a Client
type ClientOption func(*Client)

// NewClient creates a new GreyNoise client
func NewClient(apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: http.DefaultClient,
		baseURL:    defaultBaseURL,
		apiKey:     apiKey,
		userAgent:  defaultUserAgent,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithBaseURL sets a custom base URL
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// WithUserAgent sets a custom user agent
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) {
		c.userAgent = userAgent
	}
}

// QuickResponse represents a single IP lookup result
type QuickResponse struct {
	Code  string `json:"code"`
	IP    string `json:"ip"`
	Noise bool   `json:"noise"`
	Riot  bool   `json:"riot"`
}

// Tag represents a detailed tag from metadata
type Tag struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Keywords    []string `json:"keywords,omitempty"`
}

// MetadataResponse represents the response from the metadata endpoint
type MetadataResponse struct {
	Metadata []Tag `json:"metadata"`
}

// Metadata represents the metadata section of a context response
type Metadata struct {
	ASN                  string   `json:"asn"`
	City                 string   `json:"city"`
	Country              string   `json:"country"`
	CountryCode          string   `json:"country_code"`
	Organization         string   `json:"organization"`
	Category             string   `json:"category"`
	Tor                  bool     `json:"tor"`
	RDNS                 string   `json:"rdns"`
	OS                   string   `json:"os"`
	Region               string   `json:"region"`
	DestinationCountries []string `json:"destination_countries"`
	DestCountryCodes     []string `json:"destination_country_codes"`
	SourceCountry        string   `json:"source_country"`
	SourceCountryCode    string   `json:"source_country_code"`
	SensorHits           int      `json:"sensor_hits"`
	SensorCount          int      `json:"sensor_count"`
}

// ScanPort represents a port scan entry
type ScanPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// JA3Entry represents a JA3 fingerprint entry
type JA3Entry struct {
	Fingerprint string `json:"fingerprint"`
	Port        int    `json:"port"`
}

// HasshEntry represents a HASSH fingerprint entry
type HasshEntry struct {
	Fingerprint string `json:"fingerprint"`
	Port        int    `json:"port"`
}

// RawData represents the raw_data section of a context response
type RawData struct {
	Scan  []ScanPort   `json:"scan"`
	Web   interface{}  `json:"web"`
	JA3   []JA3Entry   `json:"ja3"`
	Hassh []HasshEntry `json:"hassh"`
}

// ContextResponse represents the response from the context endpoint
type ContextResponse struct {
	IP             string   `json:"ip"`
	FirstSeen      string   `json:"first_seen"`
	LastSeen       string   `json:"last_seen"`
	Seen           bool     `json:"seen"`
	Tags           []string `json:"tags"`
	Actor          string   `json:"actor"`
	Spoofable      bool     `json:"spoofable"`
	Classification string   `json:"classification"`
	CVE            []string `json:"cve"`
	Bot            bool     `json:"bot"`
	VPN            bool     `json:"vpn"`
	VPNService     string   `json:"vpn_service"`
	Metadata       Metadata `json:"metadata"`
	RawData        RawData  `json:"raw_data"`
}

// RiotResponse represents the response from the riot endpoint
type RiotResponse struct {
	IP          string `json:"ip"`
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Explanation string `json:"explanation"`
	LastUpdated string `json:"last_updated"`
	Trust       bool   `json:"trust_level"`
}

// IPLookup performs a comprehensive lookup for an IP address
func (c *Client) IPLookup(ctx context.Context, ip string) (interface{}, error) {
	// First, do quick lookup
	quick, err := c.quickLookup(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("quick lookup failed: %w", err)
	}

	var contextResp *ContextResponse
	var riotResp *RiotResponse

	// If noise is true, get context and metadata
	if quick.Noise {
		contextResp, err = c.contextLookup(ctx, ip)
		if err != nil {
			return nil, fmt.Errorf("context lookup failed: %w", err)
		}

		if len(contextResp.Tags) > 0 {
			metadata, err := c.getMetadata(ctx)
			if err != nil {
				return nil, fmt.Errorf("metadata lookup failed: %w", err)
			}
			contextResp.Tags = c.buildTagDetails(metadata, contextResp.Tags)
		}
	}

	// If riot is true, get riot information
	if quick.Riot {
		riotResp, err = c.riotLookup(ctx, ip)
		if err != nil {
			return nil, fmt.Errorf("riot lookup failed: %w", err)
		}
	}

	// Combine results based on what we got
	if contextResp != nil && riotResp != nil {
		return c.combineResponses(contextResp, riotResp)
	} else if contextResp != nil {
		return contextResp, nil
	} else if riotResp != nil {
		return riotResp, nil
	}

	return quick, nil
}

// QuickLookup performs a quick lookup for a single IP address
func (c *Client) QuickLookup(ctx context.Context, ip string) (*QuickResponse, error) {
	url := fmt.Sprintf("%s/noise/quick/%s", c.baseURL, ip)
	var result QuickResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ContextLookup performs a context lookup for a single IP address
func (c *Client) ContextLookup(ctx context.Context, ip string) (*ContextResponse, error) {
	url := fmt.Sprintf("%s/noise/context/%s", c.baseURL, ip)
	var result ContextResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RiotLookup performs a RIOT lookup for a single IP address
func (c *Client) RiotLookup(ctx context.Context, ip string) (*RiotResponse, error) {
	url := fmt.Sprintf("%s/riot/%s", c.baseURL, ip)
	var result RiotResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetMetadata retrieves the metadata information
func (c *Client) GetMetadata(ctx context.Context) (*MetadataResponse, error) {
	url := fmt.Sprintf("%s/meta/metadata", c.baseURL)
	var result MetadataResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) quickLookup(ctx context.Context, ip string) (*QuickResponse, error) {
	url := fmt.Sprintf("%s/noise/quick/%s", c.baseURL, ip)
	var result QuickResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) contextLookup(ctx context.Context, ip string) (*ContextResponse, error) {
	url := fmt.Sprintf("%s/noise/context/%s", c.baseURL, ip)
	var result ContextResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) riotLookup(ctx context.Context, ip string) (*RiotResponse, error) {
	url := fmt.Sprintf("%s/riot/%s", c.baseURL, ip)
	var result RiotResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) getMetadata(ctx context.Context) (*MetadataResponse, error) {
	url := fmt.Sprintf("%s/meta/metadata", c.baseURL)
	var result MetadataResponse
	if err := c.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) buildTagDetails(metadata *MetadataResponse, tags []string) []string {
	var detailedTags []string
	for _, tag := range tags {
		for _, detailedTag := range metadata.Metadata {
			if tag == detailedTag.Name {
				detailedTags = append(detailedTags, detailedTag.Name)
				break
			}
		}
	}
	return detailedTags
}

func (c *Client) combineResponses(context *ContextResponse, riot *RiotResponse) (map[string]interface{}, error) {
	// Convert context to map
	contextMap := make(map[string]interface{})
	contextBytes, err := json.Marshal(context)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(contextBytes, &contextMap); err != nil {
		return nil, err
	}

	// Convert riot to map
	riotMap := make(map[string]interface{})
	riotBytes, err := json.Marshal(riot)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(riotBytes, &riotMap); err != nil {
		return nil, err
	}

	// Combine maps
	for k, v := range riotMap {
		contextMap[k] = v
	}

	return contextMap, nil
}

func (c *Client) doRequest(ctx context.Context, method, url string, body interface{}, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	// Ignore 400 and 401 status codes
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		return nil
	}

	// Check other error status codes
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return nil
}

// BulkQuickLookup performs a bulk quick lookup for multiple IP addresses
// Automatically handles batching for more than 1000 IPs per request
func (c *Client) BulkQuickLookup(ctx context.Context, ips []string) ([]QuickResponse, error) {
	var allResults []QuickResponse

	// Process IPs in batches of 1000
	for i := 0; i < len(ips); i += maxIPsPerBatch {
		end := i + maxIPsPerBatch
		if end > len(ips) {
			end = len(ips)
		}
		batch := ips[i:end]

		// Process this batch
		results, err := c.bulkQuickLookupBatch(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("batch lookup failed for IPs %d-%d: %w", i, end-1, err)
		}
		allResults = append(allResults, results...)

		// Log progress for large sets
		if len(ips) > maxIPsPerBatch {
			logrus.Infof("Processed %d/%d IPs", end, len(ips))
		}
	}

	return allResults, nil
}

// bulkQuickLookupBatch handles a single batch of IPs (max 1000)
func (c *Client) bulkQuickLookupBatch(ctx context.Context, ips []string) ([]QuickResponse, error) {
	if len(ips) > maxIPsPerBatch {
		return nil, fmt.Errorf("batch size exceeds maximum of %d IPs", maxIPsPerBatch)
	}

	payload := struct {
		IPs []string `json:"ips"`
	}{
		IPs: ips,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	url := fmt.Sprintf("%s/noise/multi/quick", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	// Ignore 400 and 401 status codes
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		return []QuickResponse{}, nil
	}

	// Check other error status codes
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result []QuickResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result, nil
}
