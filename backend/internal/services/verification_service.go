package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/husa/backend/internal/models"
)

// VerificationService handles license verification submissions and admin reviews.
type VerificationService struct {
	db *sql.DB
}

// NewVerificationService creates a new VerificationService.
func NewVerificationService(db *sql.DB) *VerificationService {
	return &VerificationService{db: db}
}

// Submit creates a new verification request for a user.
func (s *VerificationService) Submit(userID string, req models.SubmitVerificationRequest) (*models.Verification, error) {
	if req.LicenseNumber == "" || req.DocumentURL == "" {
		return nil, errors.New("license_number and document_url are required")
	}

	// Prevent duplicate pending submissions.
	var pendingExists bool
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM verifications WHERE user_id = $1 AND status = 'pending')`,
		userID,
	).Scan(&pendingExists)
	if err != nil {
		return nil, fmt.Errorf("checking pending verification: %w", err)
	}
	if pendingExists {
		return nil, errors.New("a pending verification already exists")
	}

	v := &models.Verification{}
	err = s.db.QueryRow(`
		INSERT INTO verifications (user_id, license_number, document_url)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, license_number, document_url, status, reviewed_by, reviewed_at, created_at`,
		userID, req.LicenseNumber, req.DocumentURL,
	).Scan(
		&v.ID, &v.UserID, &v.LicenseNumber, &v.DocumentURL,
		&v.Status, &v.ReviewedBy, &v.ReviewedAt, &v.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting verification: %w", err)
	}

	s.writeAuditLog(userID, "verification.submit", map[string]interface{}{
		"verification_id": v.ID,
		"license_number":  req.LicenseNumber,
	})

	return v, nil
}

// GetStatus returns the latest verification record for a user.
func (s *VerificationService) GetStatus(userID string) (*models.Verification, error) {
	v := &models.Verification{}
	err := s.db.QueryRow(`
		SELECT id, user_id, license_number, document_url, status, reviewed_by, reviewed_at, created_at
		FROM verifications
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1`, userID,
	).Scan(
		&v.ID, &v.UserID, &v.LicenseNumber, &v.DocumentURL,
		&v.Status, &v.ReviewedBy, &v.ReviewedAt, &v.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("no verification found")
	}
	if err != nil {
		return nil, fmt.Errorf("fetching verification: %w", err)
	}
	return v, nil
}

// ListPending returns all pending verification requests (admin only).
func (s *VerificationService) ListPending(page, limit int) ([]models.Verification, error) {
	offset := (page - 1) * limit
	rows, err := s.db.Query(`
		SELECT id, user_id, license_number, document_url, status, reviewed_by, reviewed_at, created_at
		FROM verifications
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("listing pending verifications: %w", err)
	}
	defer rows.Close()

	var verifications []models.Verification
	for rows.Next() {
		var v models.Verification
		if err := rows.Scan(
			&v.ID, &v.UserID, &v.LicenseNumber, &v.DocumentURL,
			&v.Status, &v.ReviewedBy, &v.ReviewedAt, &v.CreatedAt,
		); err != nil {
			return nil, err
		}
		verifications = append(verifications, v)
	}
	return verifications, rows.Err()
}

// Review approves or rejects a verification request.
func (s *VerificationService) Review(verificationID, adminID string, req models.ReviewVerificationRequest) (*models.Verification, error) {
	if req.Status != "approved" && req.Status != "rejected" {
		return nil, errors.New("status must be 'approved' or 'rejected'")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	v := &models.Verification{}
	err = tx.QueryRow(`
		UPDATE verifications
		SET status = $1, reviewed_by = $2, reviewed_at = NOW()
		WHERE id = $3
		RETURNING id, user_id, license_number, document_url, status, reviewed_by, reviewed_at, created_at`,
		req.Status, adminID, verificationID,
	).Scan(
		&v.ID, &v.UserID, &v.LicenseNumber, &v.DocumentURL,
		&v.Status, &v.ReviewedBy, &v.ReviewedAt, &v.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("verification not found")
	}
	if err != nil {
		return nil, fmt.Errorf("updating verification: %w", err)
	}

	// If approved, mark the user as verified.
	if req.Status == "approved" {
		if _, err := tx.Exec(`UPDATE users SET is_verified = TRUE WHERE id = $1`, v.UserID); err != nil {
			return nil, fmt.Errorf("updating user verified status: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	s.writeAuditLog(adminID, "verification.review", map[string]interface{}{
		"verification_id": verificationID,
		"status":          req.Status,
		"target_user_id":  v.UserID,
	})

	return v, nil
}

func (s *VerificationService) writeAuditLog(userID, action string, metadata map[string]interface{}) {
	go func() {
		meta, _ := json.Marshal(metadata)
		_, _ = s.db.Exec(
			`INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)`,
			userID, action, string(meta),
		)
	}()
}
