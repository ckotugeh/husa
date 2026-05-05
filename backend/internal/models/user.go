package models

import (
	"database/sql"
	"time"
)

// User represents a row in the users table.
type User struct {
	ID              string         `json:"id"`
	FullName        string         `json:"full_name"`
	Email           string         `json:"email"`
	PasswordHash    string         `json:"-"` // never serialised to JSON
	Country         string         `json:"country"`
	Specialty       sql.NullString `json:"specialty"`
	Bio             sql.NullString `json:"bio"`
	ProfileImageURL sql.NullString `json:"profile_image_url"`
	IsVerified      bool           `json:"is_verified"`
	IsActive        bool           `json:"is_active"`
	Role            string         `json:"role"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// PublicProfile is the safe subset of User returned to other users.
type PublicProfile struct {
	ID              string    `json:"id"`
	FullName        string    `json:"full_name"`
	Country         string    `json:"country"`
	Specialty       *string   `json:"specialty,omitempty"`
	Bio             *string   `json:"bio,omitempty"`
	ProfileImageURL *string   `json:"profile_image_url,omitempty"`
	IsVerified      bool      `json:"is_verified"`
	CreatedAt       time.Time `json:"created_at"`
}

// RegisterRequest is the payload for POST /auth/register.
type RegisterRequest struct {
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Country   string `json:"country"`
	Specialty string `json:"specialty,omitempty"`
}

// LoginRequest is the payload for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UpdateProfileRequest is the payload for PUT /users/me.
type UpdateProfileRequest struct {
	FullName        string `json:"full_name,omitempty"`
	Country         string `json:"country,omitempty"`
	Specialty       string `json:"specialty,omitempty"`
	Bio             string `json:"bio,omitempty"`
	ProfileImageURL string `json:"profile_image_url,omitempty"`
}

// Follow represents a row in the follows table.
type Follow struct {
	ID          string    `json:"id"`
	FollowerID  string    `json:"follower_id"`
	FollowingID string    `json:"following_id"`
	CreatedAt   time.Time `json:"created_at"`
}
