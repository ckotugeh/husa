package services

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/husa/backend/internal/models"
)

// UserService handles user profile and follow operations.
type UserService struct {
	db *sql.DB
}

// NewUserService creates a new UserService.
func NewUserService(db *sql.DB) *UserService {
	return &UserService{db: db}
}

// GetByID fetches a user by their UUID.
func (s *UserService) GetByID(id string) (*models.User, error) {
	user := &models.User{}
	err := s.db.QueryRow(`
		SELECT id, full_name, email, password_hash, country, specialty, bio,
		       profile_image_url, is_verified, is_active, role, created_at, updated_at
		FROM users WHERE id = $1`, id,
	).Scan(
		&user.ID, &user.FullName, &user.Email, &user.PasswordHash,
		&user.Country, &user.Specialty, &user.Bio, &user.ProfileImageURL,
		&user.IsVerified, &user.IsActive, &user.Role, &user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	return user, nil
}

// UpdateProfile applies partial updates to the authenticated user's profile.
func (s *UserService) UpdateProfile(userID string, req models.UpdateProfileRequest) (*models.User, error) {
	_, err := s.db.Exec(`
		UPDATE users SET
			full_name        = COALESCE(NULLIF($1,''), full_name),
			country          = COALESCE(NULLIF($2,''), country),
			specialty        = COALESCE(NULLIF($3,''), specialty),
			bio              = COALESCE(NULLIF($4,''), bio),
			profile_image_url = COALESCE(NULLIF($5,''), profile_image_url),
			updated_at       = NOW()
		WHERE id = $6`,
		req.FullName, req.Country, req.Specialty, req.Bio, req.ProfileImageURL, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("updating profile: %w", err)
	}
	return s.GetByID(userID)
}

// Follow creates a follow relationship. Returns an error if already following.
func (s *UserService) Follow(followerID, followingID string) error {
	if followerID == followingID {
		return errors.New("cannot follow yourself")
	}
	_, err := s.db.Exec(
		`INSERT INTO follows (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		followerID, followingID,
	)
	if err != nil {
		return fmt.Errorf("following user: %w", err)
	}
	return nil
}

// Unfollow removes a follow relationship.
func (s *UserService) Unfollow(followerID, followingID string) error {
	_, err := s.db.Exec(
		`DELETE FROM follows WHERE follower_id = $1 AND following_id = $2`,
		followerID, followingID,
	)
	if err != nil {
		return fmt.Errorf("unfollowing user: %w", err)
	}
	return nil
}

// ListFollowers returns users who follow the given user.
func (s *UserService) ListFollowers(userID string, page, limit int) ([]models.PublicProfile, error) {
	offset := (page - 1) * limit
	rows, err := s.db.Query(`
		SELECT u.id, u.full_name, u.country, u.specialty, u.bio, u.profile_image_url,
		       u.is_verified, u.created_at
		FROM follows f
		JOIN users u ON u.id = f.follower_id
		WHERE f.following_id = $1
		ORDER BY f.created_at DESC
		LIMIT $2 OFFSET $3`, userID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("listing followers: %w", err)
	}
	defer rows.Close()
	return scanPublicProfiles(rows)
}

// ListFollowing returns users that the given user follows.
func (s *UserService) ListFollowing(userID string, page, limit int) ([]models.PublicProfile, error) {
	offset := (page - 1) * limit
	rows, err := s.db.Query(`
		SELECT u.id, u.full_name, u.country, u.specialty, u.bio, u.profile_image_url,
		       u.is_verified, u.created_at
		FROM follows f
		JOIN users u ON u.id = f.following_id
		WHERE f.follower_id = $1
		ORDER BY f.created_at DESC
		LIMIT $2 OFFSET $3`, userID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("listing following: %w", err)
	}
	defer rows.Close()
	return scanPublicProfiles(rows)
}

// scanPublicProfiles scans rows into a slice of PublicProfile.
func scanPublicProfiles(rows *sql.Rows) ([]models.PublicProfile, error) {
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
