package models

import (
	"database/sql"
	"time"
)

// Notification represents a row in the notifications table.
type Notification struct {
	ID          string         `json:"id"`
	UserID      string         `json:"user_id"`
	Type        string         `json:"type"`
	ReferenceID sql.NullString `json:"reference_id"`
	IsRead      bool           `json:"is_read"`
	CreatedAt   time.Time      `json:"created_at"`
}
