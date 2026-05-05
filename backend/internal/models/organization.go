package models

import (
	"database/sql"
	"time"
)

// Organization represents a row in the organizations table.
type Organization struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Country   sql.NullString `json:"country"`
	Verified  bool           `json:"verified"`
	CreatedAt time.Time      `json:"created_at"`
}

// UserOrganization represents a row in the user_organizations table.
type UserOrganization struct {
	ID             string         `json:"id"`
	UserID         string         `json:"user_id"`
	OrganizationID string         `json:"organization_id"`
	Role           sql.NullString `json:"role"`
	CreatedAt      time.Time      `json:"created_at"`
}
