package models

import "time"

// Comment represents a row in the comments table.
type Comment struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	UserID    string    `json:"user_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateCommentRequest is the payload for POST /cases/:id/comments.
type CreateCommentRequest struct {
	Content string `json:"content"`
}
