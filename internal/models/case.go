package models

import (
	"database/sql"
	"time"
)

// Case represents a row in the cases table.
type Case struct {
	ID            string         `json:"id"`
	UserID        string         `json:"user_id"`
	Title         string         `json:"title"`
	Description   string         `json:"description"`
	SpecialtyTag  sql.NullString `json:"specialty_tag"`
	IsAnonymized  bool           `json:"is_anonymized"`
	ViewsCount    int            `json:"views_count"`
	CommentsCount int            `json:"comments_count"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// CaseMedia represents a row in the case_media table.
type CaseMedia struct {
	ID        string         `json:"id"`
	CaseID    string         `json:"case_id"`
	FileURL   string         `json:"file_url"`
	FileType  sql.NullString `json:"file_type"`
	CreatedAt time.Time      `json:"created_at"`
}

// CreateCaseRequest is the payload for POST /cases.
type CreateCaseRequest struct {
	Title        string `json:"title"`
	Description  string `json:"description"`
	SpecialtyTag string `json:"specialty_tag,omitempty"`
	IsAnonymized bool   `json:"is_anonymized"`
}

// UpdateCaseRequest is the payload for PUT /cases/:id.
type UpdateCaseRequest struct {
	Title        string `json:"title,omitempty"`
	Description  string `json:"description,omitempty"`
	SpecialtyTag string `json:"specialty_tag,omitempty"`
	IsAnonymized *bool  `json:"is_anonymized,omitempty"`
}

// CaseListParams holds pagination and filter parameters for listing cases.
type CaseListParams struct {
	Page         int
	Limit        int
	SpecialtyTag string
}
