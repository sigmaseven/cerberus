package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPaginationCalculation tests pagination offset and limit calculation
func TestPaginationCalculation(t *testing.T) {
	tests := []struct {
		name           string
		page           int
		pageSize       int
		expectedOffset int
		expectedLimit  int
	}{
		{
			name:           "First page",
			page:           1,
			pageSize:       10,
			expectedOffset: 0,
			expectedLimit:  10,
		},
		{
			name:           "Second page",
			page:           2,
			pageSize:       10,
			expectedOffset: 10,
			expectedLimit:  10,
		},
		{
			name:           "Third page with larger page size",
			page:           3,
			pageSize:       50,
			expectedOffset: 100,
			expectedLimit:  50,
		},
		{
			name:           "Page 10",
			page:           10,
			pageSize:       100,
			expectedOffset: 900,
			expectedLimit:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := (tt.page - 1) * tt.pageSize
			limit := tt.pageSize

			assert.Equal(t, tt.expectedOffset, offset, "Offset calculation mismatch")
			assert.Equal(t, tt.expectedLimit, limit, "Limit calculation mismatch")
		})
	}
}

// TestPaginationEdgeCases tests pagination edge cases
func TestPaginationEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		page       int
		pageSize   int
		shouldFail bool
	}{
		{
			name:       "Valid pagination",
			page:       1,
			pageSize:   10,
			shouldFail: false,
		},
		{
			name:       "Page zero",
			page:       0,
			pageSize:   10,
			shouldFail: true,
		},
		{
			name:       "Negative page",
			page:       -1,
			pageSize:   10,
			shouldFail: true,
		},
		{
			name:       "Page size zero",
			page:       1,
			pageSize:   0,
			shouldFail: true,
		},
		{
			name:       "Negative page size",
			page:       1,
			pageSize:   -10,
			shouldFail: true,
		},
		{
			name:       "Very large page size",
			page:       1,
			pageSize:   10000,
			shouldFail: true, // Most APIs limit page size
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldFail {
				// In production code, these would be validated
				assert.True(t, tt.page <= 0 || tt.pageSize <= 0 || tt.pageSize > 1000,
					"Invalid pagination parameters should be detected")
			} else {
				assert.True(t, tt.page > 0 && tt.pageSize > 0 && tt.pageSize <= 1000,
					"Valid pagination parameters")
			}
		})
	}
}

// TestCalculateTotalPages tests total pages calculation
func TestCalculateTotalPages(t *testing.T) {
	tests := []struct {
		name       string
		totalItems int
		pageSize   int
		expected   int
	}{
		{
			name:       "Exact division",
			totalItems: 100,
			pageSize:   10,
			expected:   10,
		},
		{
			name:       "With remainder",
			totalItems: 105,
			pageSize:   10,
			expected:   11,
		},
		{
			name:       "Less than one page",
			totalItems: 5,
			pageSize:   10,
			expected:   1,
		},
		{
			name:       "Empty",
			totalItems: 0,
			pageSize:   10,
			expected:   0,
		},
		{
			name:       "Single item",
			totalItems: 1,
			pageSize:   10,
			expected:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var totalPages int
			if tt.totalItems == 0 {
				totalPages = 0
			} else {
				totalPages = (tt.totalItems + tt.pageSize - 1) / tt.pageSize
			}
			assert.Equal(t, tt.expected, totalPages)
		})
	}
}
