package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/husa/backend/internal/middleware"
	"github.com/husa/backend/internal/models"
	"github.com/husa/backend/internal/services"
)

// UserHandler handles user profile and follow endpoints.
type UserHandler struct {
	userSvc *services.UserService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(userSvc *services.UserService) *UserHandler {
	return &UserHandler{userSvc: userSvc}
}

// GetMe handles GET /api/v1/users/me.
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	user, err := h.userSvc.GetByID(userID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error(), "USER_NOT_FOUND")
		return
	}
	respondJSON(w, http.StatusOK, user)
}

// UpdateMe handles PUT /api/v1/users/me.
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	var req models.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	user, err := h.userSvc.UpdateProfile(userID, req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "UPDATE_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, user)
}

// GetUser handles GET /api/v1/users/:id.
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.userSvc.GetByID(id)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error(), "USER_NOT_FOUND")
		return
	}

	// Return a public profile (no email, no password hash).
	profile := models.PublicProfile{
		ID:         user.ID,
		FullName:   user.FullName,
		Country:    user.Country,
		IsVerified: user.IsVerified,
		CreatedAt:  user.CreatedAt,
	}
	if user.Specialty.Valid {
		profile.Specialty = &user.Specialty.String
	}
	if user.Bio.Valid {
		profile.Bio = &user.Bio.String
	}
	if user.ProfileImageURL.Valid {
		profile.ProfileImageURL = &user.ProfileImageURL.String
	}
	respondJSON(w, http.StatusOK, profile)
}

// Follow handles POST /api/v1/users/:id/follow.
func (h *UserHandler) Follow(w http.ResponseWriter, r *http.Request) {
	followerID := middleware.GetUserID(r)
	followingID := chi.URLParam(r, "id")

	if err := h.userSvc.Follow(followerID, followingID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "FOLLOW_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "followed successfully"})
}

// Unfollow handles DELETE /api/v1/users/:id/follow.
func (h *UserHandler) Unfollow(w http.ResponseWriter, r *http.Request) {
	followerID := middleware.GetUserID(r)
	followingID := chi.URLParam(r, "id")

	if err := h.userSvc.Unfollow(followerID, followingID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "UNFOLLOW_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "unfollowed successfully"})
}

// ListFollowers handles GET /api/v1/users/:id/followers.
func (h *UserHandler) ListFollowers(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	page, limit := parsePagination(r)

	followers, err := h.userSvc.ListFollowers(userID, page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if followers == nil {
		followers = []models.PublicProfile{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": followers, "page": page, "limit": limit,
	})
}

// ListFollowing handles GET /api/v1/users/:id/following.
func (h *UserHandler) ListFollowing(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	page, limit := parsePagination(r)

	following, err := h.userSvc.ListFollowing(userID, page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if following == nil {
		following = []models.PublicProfile{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": following, "page": page, "limit": limit,
	})
}
