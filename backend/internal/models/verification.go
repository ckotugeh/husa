package models

import (
	"database/sql"
	"time"
)

// Verification represents a row in the verifications table.
type Verification struct {
	ID             string         `json:"id"`
	UserID         string         `json:"user_id"`
	LicenseNumber  string         `json:"license_number"`
	DocumentURL    string         `json:"document_url"`
	Status         string         `json:"status"` // pending | approved | rejected
	ReviewedBy     sql.NullString `json:"reviewed_by"`
	ReviewedAt     sql.NullTime   `json:"reviewed_at"`
	CreatedAt      time.Time      `json:"created_at"`
}

// SubmitVerificationRequest is the payload for POST /verification/submit.
type SubmitVerificationRequest struct {
	LicenseNumber string `json:"license_number"`
	DocumentURL   string `json:"document_url"`
}

// ReviewVerificationRequest is the payload for PUT /admin/verifications/:id.
type ReviewVerificationRequest struct {
	Status string `json:"status"` // approved | rejected
}
