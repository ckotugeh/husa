package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/husa/backend/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles registration, login, and token operations.
type AuthService struct {
	db                     *sql.DB
	jwtSecret              string
	jwtExpiryHours         int
	refreshTokenExpiryDays int
}

// NewAuthService creates a new AuthService.
func NewAuthService(db *sql.DB, jwtSecret string, jwtExpiryHours, refreshTokenExpiryDays int) *AuthService {
	return &AuthService{
		db:                     db,
		jwtSecret:              jwtSecret,
		jwtExpiryHours:         jwtExpiryHours,
		refreshTokenExpiryDays: refreshTokenExpiryDays,
	}
}

// TokenPair holds an access token and a refresh token.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// Register creates a new user account and returns a token pair.
func (s *AuthService) Register(req models.RegisterRequest) (*models.User, *TokenPair, error) {
	if req.FullName == "" || req.Email == "" || req.Password == "" || req.Country == "" {
		return nil, nil, errors.New("full_name, email, password, and country are required")
	}
	if len(req.Password) < 8 {
		return nil, nil, errors.New("password must be at least 8 characters")
	}

	// Check for duplicate email.
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, req.Email).Scan(&exists)
	if err != nil {
		return nil, nil, fmt.Errorf("checking email: %w", err)
	}
	if exists {
		return nil, nil, errors.New("email already registered")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, nil, fmt.Errorf("hashing password: %w", err)
	}

	user := &models.User{}
	err = s.db.QueryRow(`
		INSERT INTO users (full_name, email, password_hash, country, specialty, role)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), 'user')
		RETURNING id, full_name, email, password_hash, country, specialty, bio,
		          profile_image_url, is_verified, is_active, role, created_at, updated_at`,
		req.FullName, req.Email, string(hash), req.Country, req.Specialty,
	).Scan(
		&user.ID, &user.FullName, &user.Email, &user.PasswordHash,
		&user.Country, &user.Specialty, &user.Bio, &user.ProfileImageURL,
		&user.IsVerified, &user.IsActive, &user.Role, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("inserting user: %w", err)
	}

	s.writeAuditLog(user.ID, "user.register", map[string]interface{}{"email": user.Email})

	tokens, err := s.generateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

// Login validates credentials and returns a token pair.
func (s *AuthService) Login(req models.LoginRequest) (*models.User, *TokenPair, error) {
	if req.Email == "" || req.Password == "" {
		return nil, nil, errors.New("email and password are required")
	}

	user := &models.User{}
	err := s.db.QueryRow(`
		SELECT id, full_name, email, password_hash, country, specialty, bio,
		       profile_image_url, is_verified, is_active, role, created_at, updated_at
		FROM users WHERE email = $1`, req.Email,
	).Scan(
		&user.ID, &user.FullName, &user.Email, &user.PasswordHash,
		&user.Country, &user.Specialty, &user.Bio, &user.ProfileImageURL,
		&user.IsVerified, &user.IsActive, &user.Role, &user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil, errors.New("invalid credentials")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("fetching user: %w", err)
	}

	if !user.IsActive {
		return nil, nil, errors.New("account is deactivated")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, nil, errors.New("invalid credentials")
	}

	s.writeAuditLog(user.ID, "user.login", map[string]interface{}{"email": user.Email})

	tokens, err := s.generateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

// RefreshToken validates a refresh token and issues a new token pair.
func (s *AuthService) RefreshToken(refreshToken string) (*TokenPair, error) {
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	tokenType, _ := claims["type"].(string)
	if tokenType != "refresh" {
		return nil, errors.New("not a refresh token")
	}

	userID, _ := claims["sub"].(string)
	role, _ := claims["role"].(string)

	return s.generateTokenPair(userID, role)
}

// ValidateAccessToken parses and validates an access token, returning the claims.
func (s *AuthService) ValidateAccessToken(tokenStr string) (userID, role string, err error) {
	claims, err := s.parseToken(tokenStr)
	if err != nil {
		return "", "", errors.New("invalid or expired token")
	}

	tokenType, _ := claims["type"].(string)
	if tokenType != "access" {
		return "", "", errors.New("not an access token")
	}

	userID, _ = claims["sub"].(string)
	role, _ = claims["role"].(string)
	return userID, role, nil
}

// generateTokenPair creates a new access + refresh token pair.
func (s *AuthService) generateTokenPair(userID, role string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(time.Duration(s.jwtExpiryHours) * time.Hour)
	refreshExpiry := now.Add(time.Duration(s.refreshTokenExpiryDays) * 24 * time.Hour)

	accessClaims := jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"type": "access",
		"iat":  now.Unix(),
		"exp":  accessExpiry.Unix(),
		"jti":  uuid.New().String(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessSigned, err := accessToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	refreshClaims := jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"type": "refresh",
		"iat":  now.Unix(),
		"exp":  refreshExpiry.Unix(),
		"jti":  uuid.New().String(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshSigned, err := refreshToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, fmt.Errorf("signing refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessSigned,
		RefreshToken: refreshSigned,
		ExpiresIn:    s.jwtExpiryHours * 3600,
	}, nil
}

// parseToken parses a JWT and returns its claims.
func (s *AuthService) parseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// writeAuditLog inserts an audit log entry asynchronously (best-effort).
func (s *AuthService) writeAuditLog(userID, action string, metadata map[string]interface{}) {
	go func() {
		meta, _ := json.Marshal(metadata)
		_, _ = s.db.Exec(
			`INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)`,
			userID, action, string(meta),
		)
	}()
}
