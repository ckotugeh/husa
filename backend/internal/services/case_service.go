package services

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/husa/backend/internal/models"
)

// CaseService handles clinical case CRUD and feed operations.
type CaseService struct {
	db *sql.DB
}

// NewCaseService creates a new CaseService.
func NewCaseService(db *sql.DB) *CaseService {
	return &CaseService{db: db}
}

// Create inserts a new case and returns it.
func (s *CaseService) Create(userID string, req models.CreateCaseRequest) (*models.Case, error) {
	if req.Title == "" || req.Description == "" {
		return nil, errors.New("title and description are required")
	}

	c := &models.Case{}
	err := s.db.QueryRow(`
		INSERT INTO cases (user_id, title, description, specialty_tag, is_anonymized)
		VALUES ($1, $2, $3, NULLIF($4,''), $5)
		RETURNING id, user_id, title, description, specialty_tag, is_anonymized,
		          views_count, comments_count, created_at, updated_at`,
		userID, req.Title, req.Description, req.SpecialtyTag, req.IsAnonymized,
	).Scan(
		&c.ID, &c.UserID, &c.Title, &c.Description, &c.SpecialtyTag,
		&c.IsAnonymized, &c.ViewsCount, &c.CommentsCount, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating case: %w", err)
	}
	return c, nil
}

// GetByID fetches a single case and increments its view count.
func (s *CaseService) GetByID(id string) (*models.Case, error) {
	// Increment view count (best-effort, non-blocking).
	go func() {
		_, _ = s.db.Exec(`UPDATE cases SET views_count = views_count + 1 WHERE id = $1`, id)
	}()

	c := &models.Case{}
	err := s.db.QueryRow(`
		SELECT id, user_id, title, description, specialty_tag, is_anonymized,
		       views_count, comments_count, created_at, updated_at
		FROM cases WHERE id = $1`, id,
	).Scan(
		&c.ID, &c.UserID, &c.Title, &c.Description, &c.SpecialtyTag,
		&c.IsAnonymized, &c.ViewsCount, &c.CommentsCount, &c.CreatedAt, &c.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("case not found")
	}
	if err != nil {
		return nil, fmt.Errorf("fetching case: %w", err)
	}
	return c, nil
}

// List returns a paginated list of cases, optionally filtered by specialty.
func (s *CaseService) List(params models.CaseListParams) ([]models.Case, error) {
	offset := (params.Page - 1) * params.Limit

	var (
		rows *sql.Rows
		err  error
	)

	if params.SpecialtyTag != "" {
		rows, err = s.db.Query(`
			SELECT id, user_id, title, description, specialty_tag, is_anonymized,
			       views_count, comments_count, created_at, updated_at
			FROM cases
			WHERE specialty_tag = $1
			ORDER BY created_at DESC
			LIMIT $2 OFFSET $3`, params.SpecialtyTag, params.Limit, offset,
		)
	} else {
		rows, err = s.db.Query(`
			SELECT id, user_id, title, description, specialty_tag, is_anonymized,
			       views_count, comments_count, created_at, updated_at
			FROM cases
			ORDER BY created_at DESC
			LIMIT $1 OFFSET $2`, params.Limit, offset,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing cases: %w", err)
	}
	defer rows.Close()

	return scanCases(rows)
}

// Update applies partial updates to a case. Only the owner may update.
func (s *CaseService) Update(caseID, userID string, req models.UpdateCaseRequest) (*models.Case, error) {
	// Verify ownership.
	var ownerID string
	err := s.db.QueryRow(`SELECT user_id FROM cases WHERE id = $1`, caseID).Scan(&ownerID)
	if err == sql.ErrNoRows {
		return nil, errors.New("case not found")
	}
	if err != nil {
		return nil, fmt.Errorf("fetching case owner: %w", err)
	}
	if ownerID != userID {
		return nil, errors.New("forbidden: not the case owner")
	}

	isAnon := sql.NullBool{}
	if req.IsAnonymized != nil {
		isAnon = sql.NullBool{Bool: *req.IsAnonymized, Valid: true}
	}

	_, err = s.db.Exec(`
		UPDATE cases SET
			title         = COALESCE(NULLIF($1,''), title),
			description   = COALESCE(NULLIF($2,''), description),
			specialty_tag = COALESCE(NULLIF($3,''), specialty_tag),
			is_anonymized = CASE WHEN $4 THEN $5 ELSE is_anonymized END,
			updated_at    = NOW()
		WHERE id = $6`,
		req.Title, req.Description, req.SpecialtyTag,
		isAnon.Valid, isAnon.Bool,
		caseID,
	)
	if err != nil {
		return nil, fmt.Errorf("updating case: %w", err)
	}
	return s.GetByID(caseID)
}

// Delete removes a case. Only the owner may delete.
func (s *CaseService) Delete(caseID, userID string) error {
	result, err := s.db.Exec(
		`DELETE FROM cases WHERE id = $1 AND user_id = $2`, caseID, userID,
	)
	if err != nil {
		return fmt.Errorf("deleting case: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return errors.New("case not found or not the owner")
	}
	return nil
}

// scanCases scans rows into a slice of Case.
func scanCases(rows *sql.Rows) ([]models.Case, error) {
	var cases []models.Case
	for rows.Next() {
		var c models.Case
		if err := rows.Scan(
			&c.ID, &c.UserID, &c.Title, &c.Description, &c.SpecialtyTag,
			&c.IsAnonymized, &c.ViewsCount, &c.CommentsCount, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, rows.Err()
}
