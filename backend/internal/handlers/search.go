package handlers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/husa/backend/internal/models"
)

// SearchHandler handles full-text search across users and cases.
type SearchHandler struct {
	db *sql.DB
}

// NewSearchHandler creates a new SearchHandler.
func NewSearchHandler(db *sql.DB) *SearchHandler {
	return &SearchHandler{db: db}
}

// Search handles GET /api/v1/search?q=&type=users|cases.
func (h *SearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	searchType := r.URL.Query().Get("type")
	page, limit := parsePagination(r)

	if q == "" {
		respondError(w, http.StatusBadRequest, "query parameter 'q' is required", "BAD_REQUEST")
		return
	}

	result := map[string]interface{}{}

	if searchType == "" || searchType == "users" {
		users, err := h.searchUsers(q, page, limit)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("user search failed: %v", err), "SEARCH_FAILED")
			return
		}
		if users == nil {
			users = []models.PublicProfile{}
		}
		result["users"] = users
	}

	if searchType == "" || searchType == "cases" {
		cases, err := h.searchCases(q, page, limit)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("case search failed: %v", err), "SEARCH_FAILED")
			return
		}
		if cases == nil {
			cases = []models.Case{}
		}
		result["cases"] = cases
	}

	result["query"] = q
	result["page"] = page
	result["limit"] = limit

	respondJSON(w, http.StatusOK, result)
}

// searchUsers performs a trigram-based full-text search on user names.
func (h *SearchHandler) searchUsers(q string, page, limit int) ([]models.PublicProfile, error) {
	offset := (page - 1) * limit
	rows, err := h.db.Query(`
		SELECT id, full_name, country, specialty, bio, profile_image_url, is_verified, created_at
		FROM users
		WHERE full_name ILIKE '%' || $1 || '%'
		   OR specialty ILIKE '%' || $1 || '%'
		ORDER BY similarity(full_name, $1) DESC
		LIMIT $2 OFFSET $3`, q, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []models.PublicProfile
	for rows.Next() {
		var p models.PublicProfile
		var specialty, bio, profileImageURL sql.NullString
		if err := rows.Scan(
			&p.ID, &p.FullName, &p.Country,
			&specialty, &bio, &profileImageURL,
			&p.IsVerified, &p.CreatedAt,
		); err != nil {
			return nil, err
		}
		if specialty.Valid {
			p.Specialty = &specialty.String
		}
		if bio.Valid {
			p.Bio = &bio.String
		}
		if profileImageURL.Valid {
			p.ProfileImageURL = &profileImageURL.String
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// searchCases performs a trigram-based full-text search on case titles and descriptions.
func (h *SearchHandler) searchCases(q string, page, limit int) ([]models.Case, error) {
	offset := (page - 1) * limit
	rows, err := h.db.Query(`
		SELECT id, user_id, title, description, specialty_tag, is_anonymized,
		       views_count, comments_count, created_at, updated_at
		FROM cases
		WHERE title ILIKE '%' || $1 || '%'
		   OR description ILIKE '%' || $1 || '%'
		   OR specialty_tag ILIKE '%' || $1 || '%'
		ORDER BY similarity(title, $1) DESC
		LIMIT $2 OFFSET $3`, q, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
