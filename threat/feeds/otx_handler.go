package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cerberus/core"
)

// =============================================================================
// AlienVault OTX Feed Handler
// =============================================================================

const (
	// OTX API base URL
	otxBaseURL = "https://otx.alienvault.com/api/v1"

	// Default page size for OTX API
	otxDefaultPageSize = 50
)

// OTXHandler implements IOCFeedHandler for AlienVault OTX
type OTXHandler struct {
	httpClient *http.Client
}

// NewOTXHandler creates a new OTX feed handler
func NewOTXHandler() *OTXHandler {
	return &OTXHandler{
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Type returns the feed type this handler supports
func (h *OTXHandler) Type() IOCFeedType {
	return IOCFeedTypeOTX
}

// Validate checks if the feed configuration is valid
func (h *OTXHandler) Validate(feed *IOCFeed) error {
	// OTX requires API key
	if feed.AuthConfig == nil {
		return ErrMissingAuth
	}

	apiKey, ok := feed.AuthConfig["api_key"].(string)
	if !ok || apiKey == "" {
		return fmt.Errorf("%w: OTX API key is required", ErrMissingAuth)
	}

	return nil
}

// Test verifies connectivity to the OTX API
func (h *OTXHandler) Test(ctx context.Context, feed *IOCFeed) error {
	if err := h.Validate(feed); err != nil {
		return err
	}

	// Test API connectivity by fetching user info
	reqURL := fmt.Sprintf("%s/user/me", otxBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}

	h.addAuth(req, feed)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrAuthFailed
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrConnectionFailed, resp.StatusCode)
	}

	return nil
}

// FetchIOCs retrieves IOCs from OTX
func (h *OTXHandler) FetchIOCs(ctx context.Context, feed *IOCFeed, since *time.Time) ([]*FetchedIOC, error) {
	if err := h.Validate(feed); err != nil {
		return nil, err
	}

	var allIOCs []*FetchedIOC

	// Fetch from specific pulses if configured
	if len(feed.PulseIDs) > 0 {
		for _, pulseID := range feed.PulseIDs {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			iocs, err := h.fetchPulseIndicators(ctx, feed, pulseID)
			if err != nil {
				continue // Log and continue with other pulses
			}
			allIOCs = append(allIOCs, iocs...)
		}
	} else {
		// Fetch subscribed pulses
		iocs, err := h.fetchSubscribedPulses(ctx, feed, since)
		if err != nil {
			return nil, err
		}
		allIOCs = iocs
	}

	if len(allIOCs) == 0 {
		return nil, ErrNoIOCsFound
	}

	return allIOCs, nil
}

// Close releases any resources held by the handler
func (h *OTXHandler) Close() error {
	h.httpClient.CloseIdleConnections()
	return nil
}

// =============================================================================
// OTX API Types
// =============================================================================

// otxPulseResponse represents the OTX API response for pulses
type otxPulseResponse struct {
	Results    []otxPulse `json:"results"`
	Count      int        `json:"count"`
	NextURL    string     `json:"next"`
	PrevURL    string     `json:"previous"`
}

// otxPulse represents an OTX pulse
type otxPulse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	AuthorName  string         `json:"author_name"`
	Modified    string         `json:"modified"`
	Created     string         `json:"created"`
	Tags        []string       `json:"tags"`
	References  []string       `json:"references"`
	Indicators  []otxIndicator `json:"indicators"`
	TLP         string         `json:"tlp"`
}

// otxIndicator represents an OTX indicator
type otxIndicator struct {
	ID          int64  `json:"id"`
	Indicator   string `json:"indicator"`
	Type        string `json:"type"`
	Created     string `json:"created"`
	Content     string `json:"content"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IsActive    int    `json:"is_active"`
	Role        string `json:"role"`
}

// =============================================================================
// Internal Methods
// =============================================================================

// fetchSubscribedPulses fetches IOCs from subscribed pulses
func (h *OTXHandler) fetchSubscribedPulses(ctx context.Context, feed *IOCFeed, since *time.Time) ([]*FetchedIOC, error) {
	var allIOCs []*FetchedIOC
	page := 1
	pageSize := otxDefaultPageSize

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Build request URL
		params := url.Values{}
		params.Set("page", strconv.Itoa(page))
		params.Set("limit", strconv.Itoa(pageSize))
		if since != nil {
			params.Set("modified_since", since.Format("2006-01-02T15:04:05"))
		}

		reqURL := fmt.Sprintf("%s/pulses/subscribed?%s", otxBaseURL, params.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}

		h.addAuth(req, feed)

		resp, err := h.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return nil, ErrAuthFailed
			}
			return nil, fmt.Errorf("%w: HTTP %d", ErrConnectionFailed, resp.StatusCode)
		}

		var pulseResp otxPulseResponse
		if err := json.Unmarshal(body, &pulseResp); err != nil {
			return nil, fmt.Errorf("failed to parse OTX response: %w", err)
		}

		// Process each pulse
		for _, pulse := range pulseResp.Results {
			iocs := h.convertPulseToIOCs(pulse, feed)
			allIOCs = append(allIOCs, iocs...)
		}

		// Check if there are more pages
		if pulseResp.NextURL == "" || len(pulseResp.Results) == 0 {
			break
		}
		page++
	}

	return allIOCs, nil
}

// fetchPulseIndicators fetches indicators from a specific pulse
func (h *OTXHandler) fetchPulseIndicators(ctx context.Context, feed *IOCFeed, pulseID string) ([]*FetchedIOC, error) {
	reqURL := fmt.Sprintf("%s/pulses/%s/indicators", otxBaseURL, pulseID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	h.addAuth(req, feed)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrConnectionFailed, resp.StatusCode)
	}

	var indicatorResp struct {
		Results []otxIndicator `json:"results"`
	}
	if err := json.Unmarshal(body, &indicatorResp); err != nil {
		return nil, fmt.Errorf("failed to parse OTX indicators: %w", err)
	}

	var iocs []*FetchedIOC
	for _, ind := range indicatorResp.Results {
		ioc := h.convertIndicatorToIOC(ind, pulseID, nil, feed)
		if ioc != nil {
			iocs = append(iocs, ioc)
		}
	}

	return iocs, nil
}

// convertPulseToIOCs converts a pulse to FetchedIOC slice
func (h *OTXHandler) convertPulseToIOCs(pulse otxPulse, feed *IOCFeed) []*FetchedIOC {
	var iocs []*FetchedIOC

	for _, ind := range pulse.Indicators {
		ioc := h.convertIndicatorToIOC(ind, pulse.ID, &pulse, feed)
		if ioc != nil {
			iocs = append(iocs, ioc)
		}
	}

	return iocs
}

// convertIndicatorToIOC converts an OTX indicator to FetchedIOC
func (h *OTXHandler) convertIndicatorToIOC(ind otxIndicator, pulseID string, pulse *otxPulse, feed *IOCFeed) *FetchedIOC {
	iocType := h.mapOTXType(ind.Type)
	if iocType == "" {
		// Filter by include/exclude types
		return nil
	}

	// Apply type filters
	if len(feed.IncludeTypes) > 0 {
		found := false
		for _, t := range feed.IncludeTypes {
			if t == iocType {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	for _, t := range feed.ExcludeTypes {
		if t == iocType {
			return nil
		}
	}

	value := strings.TrimSpace(ind.Indicator)
	if value == "" {
		return nil
	}

	ioc := &FetchedIOC{
		Type:       iocType,
		Value:      value,
		ExternalID: fmt.Sprintf("otx-%s-%d", pulseID, ind.ID),
		Severity:   core.IOCSeverityMedium, // Default severity
	}

	// Set description from indicator or pulse
	if ind.Description != "" {
		ioc.Description = ind.Description
	} else if ind.Title != "" {
		ioc.Description = ind.Title
	} else if pulse != nil && pulse.Name != "" {
		ioc.Description = fmt.Sprintf("From OTX pulse: %s", pulse.Name)
	}

	// Parse timestamps
	if ind.Created != "" {
		if t, err := time.Parse("2006-01-02T15:04:05", ind.Created); err == nil {
			ioc.FirstSeen = &t
		}
	}

	// Add pulse information
	if pulse != nil {
		ioc.Tags = append(ioc.Tags, pulse.Tags...)
		ioc.References = pulse.References

		// Add OTX pulse URL as reference
		pulseURL := fmt.Sprintf("https://otx.alienvault.com/pulse/%s", pulse.ID)
		ioc.References = append(ioc.References, pulseURL)

		// Set severity based on TLP if available
		if pulse.TLP != "" {
			switch strings.ToUpper(pulse.TLP) {
			case "RED":
				ioc.Severity = core.IOCSeverityCritical
			case "AMBER":
				ioc.Severity = core.IOCSeverityHigh
			case "GREEN":
				ioc.Severity = core.IOCSeverityMedium
			case "WHITE":
				ioc.Severity = core.IOCSeverityLow
			}
		}
	}

	// Add OTX-specific tag
	ioc.Tags = append(ioc.Tags, "otx")

	// Store raw data
	ioc.RawData = map[string]interface{}{
		"otx_indicator_id": ind.ID,
		"otx_pulse_id":     pulseID,
		"otx_type":         ind.Type,
		"otx_role":         ind.Role,
		"otx_is_active":    ind.IsActive,
	}

	return ioc
}

// mapOTXType maps OTX indicator types to core IOC types
func (h *OTXHandler) mapOTXType(otxType string) core.IOCType {
	switch strings.ToLower(otxType) {
	case "ipv4", "ipv6":
		return core.IOCTypeIP
	case "domain", "hostname":
		return core.IOCTypeDomain
	case "url", "uri":
		return core.IOCTypeURL
	case "md5", "sha1", "sha256", "sha512", "filehash-md5", "filehash-sha1",
		"filehash-sha256", "filehash-sha512", "file_hash_md5", "file_hash_sha1",
		"file_hash_sha256", "file_hash_sha512":
		return core.IOCTypeHash
	case "email":
		return core.IOCTypeEmail
	case "filepath", "file_path":
		return core.IOCTypeFilename
	case "cve":
		return core.IOCTypeCVE
	case "cidr":
		return core.IOCTypeCIDR
	case "useragent", "user-agent":
		return core.IOCTypeUserAgent
	default:
		return ""
	}
}

// addAuth adds OTX authentication header
func (h *OTXHandler) addAuth(req *http.Request, feed *IOCFeed) {
	if feed.AuthConfig == nil {
		return
	}

	if apiKey, ok := feed.AuthConfig["api_key"].(string); ok && apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", apiKey)
	}
}

// Ensure OTXHandler satisfies interface at compile time
var _ IOCFeedHandler = (*OTXHandler)(nil)
