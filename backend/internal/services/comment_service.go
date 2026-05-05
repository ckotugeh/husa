package services

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/husa/backend/internal/models"
)

// CommentService handles comment creation, listing, and deletion.
type CommentService struct {
	db *sql.DB
}

// NewCommentService creates a new CommentService.
func NewCommentService(db *sql.DB) *CommentService {
	return &CommentService{db: db}
}

// Create adds a comment to a case and increments the case's comment count.
func (s *CommentService) Create(caseID, userID string, req models.CreateCommentRequest) (*models.Comment, error) {
	if req.Content == "" {
		return nil, errors.New("content is required")
	}

	// Verify the case exists.
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM cases WHERE id = $1)`, caseID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("checking case: %w", err)
	}
	if !exists {
		return nil, errors.New("case not found")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	c := &models.Comment{}
	err = tx.QueryRow(`
		INSERT INTO comments (case_id, user_id, content)
		VALUES ($1, $2, $3)
		RETURNING id, case_id, user_id, content, created_at`,
		caseID, userID, req.Content,
	).Scan(&c.ID, &c.CaseID, &c.UserID, &c.Content, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting comment: %w", err)
	}

	_, err = tx.Exec(`UPDATE cases SET comments_count = comments_count + 1 WHERE id = $1`, caseID)
	if err != nil {
		return nil, fmt.Errorf("updating comment count: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return c, nil
}

// ListByCaseID returns all comments for a case, newest first.
func (s *CommentService) ListByCaseID(caseID string, page, limit int) ([]models.Comment, error) {
	offset := (page - 1) * limit
	rows, err := s.db.Query(`
		SELECT id, case_id, user_id, content, created_at
		FROM comments
		WHERE case_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`, caseID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("listing comments: %w", err)
	}
	defer rows.Close()

	var comments []models.Comment
	for rows.Next() {
		var c models.Comment
		if err := rows.Scan(&c.ID, &c.CaseID, &c.UserID, &c.Content, &c.CreatedAt); err != nil {
			return nil, err
		}
		comments = append(comments, c)
	}
	return comments, rows.Err()
}

// Delete removes a comment. Only the owner may delete.
func (s *CommentService) Delete(commentID, userID string) error {
	// Fetch the comment to get the case_id for decrementing the count.
	var caseID string
	var ownerID string
	err := s.db.QueryRow(`SELECT case_id, user_id FROM comments WHERE id = $1`, commentID).Scan(&caseID, &ownerID)
	if err == sql.ErrNoRows {
		return errors.New("comment not found")
	}
	if err != nil {
		return fmt.Errorf("fetching comment: %w", err)
	}
	if ownerID != userID {
		return errors.New("forbidden: not the comment owner")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`DELETE FROM comments WHERE id = $1`, commentID); err != nil {
		return fmt.Errorf("deleting comment: %w", err)
	}
	if _, err := tx.Exec(`UPDATE cases SET comments_count = GREATEST(comments_count - 1, 0) WHERE id = $1`, caseID); err != nil {
		return fmt.Errorf("updating comment count: %w", err)
	}

	return tx.Commit()
}
