package api

import (
	"math"
	"net/http"
	"strconv"
)

// PaginationParams holds pagination query parameters
type PaginationParams struct {
	Page  int `json:"page"`  // 1-based page number
	Limit int `json:"limit"` // Items per page
}

// PaginationResponse is a generic paginated response wrapper
type PaginationResponse struct {
	Items      interface{} `json:"items"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	Limit      int         `json:"limit"`
	TotalPages int         `json:"total_pages"`
}

// ParsePaginationParams extracts pagination parameters from HTTP request
func ParsePaginationParams(r *http.Request, defaultLimit int, maxLimit int) PaginationParams {
	page := 1
	limit := defaultLimit

	// Parse page parameter
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			// Add bounds checking to prevent abuse
			if parsed > 1000000 {
				page = 1000000 // Cap at reasonable maximum
			} else {
				page = parsed
			}
		}
	}

	// Parse limit parameter
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
			// Cap at max limit
			if limit > maxLimit {
				limit = maxLimit
			}
		}
	}

	return PaginationParams{
		Page:  page,
		Limit: limit,
	}
}

// CalculateOffset converts page and limit to MongoDB skip/offset
func (p PaginationParams) CalculateOffset() int {
	// Prevent integer overflow by checking bounds
	pageMinusOne := p.Page - 1
	if pageMinusOne <= 0 {
		return 0
	}

	// Check for potential overflow before multiplication
	if p.Limit > 0 && pageMinusOne > math.MaxInt/p.Limit {
		// Return max int to indicate overflow (will likely cause query to return no results)
		return math.MaxInt
	}

	return pageMinusOne * p.Limit
}

// NewPaginationResponse creates a paginated response
func NewPaginationResponse(items interface{}, total int64, page int, limit int) PaginationResponse {
	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	return PaginationResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
	}
}
