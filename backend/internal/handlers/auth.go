package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/husa/backend/internal/models"
	"github.com/husa/backend/internal/services"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	authSvc *services.AuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authSvc *services.AuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

// Register handles POST /api/v1/auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	user, tokens, err := h.authSvc.Register(req)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "REGISTRATION_FAILED")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"user":   user,
		"tokens": tokens,
	})
}

// Login handles POST /api/v1/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	user, tokens, err := h.authSvc.Login(req)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error(), "LOGIN_FAILED")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user":   user,
		"tokens": tokens,
	})
}

// Refresh handles POST /api/v1/auth/refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "refresh_token is required", "BAD_REQUEST")
		return
	}

	tokens, err := h.authSvc.RefreshToken(body.RefreshToken)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error(), "REFRESH_FAILED")
		return
	}

	respondJSON(w, http.StatusOK, tokens)
}

// Logout handles POST /api/v1/auth/logout.
// Token invalidation is client-side for stateless JWTs; this endpoint exists
// for future blocklist integration and audit logging.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}
