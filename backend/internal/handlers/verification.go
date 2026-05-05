package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/husa/backend/internal/middleware"
	"github.com/husa/backend/internal/models"
	"github.com/husa/backend/internal/services"
)

// VerificationHandler handles verification submission and admin review endpoints.
type VerificationHandler struct {
	verifSvc *services.VerificationService
}

// NewVerificationHandler creates a new VerificationHandler.
func NewVerificationHandler(verifSvc *services.VerificationService) *VerificationHandler {
	return &VerificationHandler{verifSvc: verifSvc}
}

// Submit handles POST /api/v1/verification/submit.
func (h *VerificationHandler) Submit(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	var req models.SubmitVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	v, err := h.verifSvc.Submit(userID, req)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "SUBMIT_FAILED")
		return
	}
	respondJSON(w, http.StatusCreated, v)
}

// GetStatus handles GET /api/v1/verification/status.
func (h *VerificationHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	v, err := h.verifSvc.GetStatus(userID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error(), "NOT_FOUND")
		return
	}
	respondJSON(w, http.StatusOK, v)
}

// ListPending handles GET /api/v1/admin/verifications.
func (h *VerificationHandler) ListPending(w http.ResponseWriter, r *http.Request) {
	page, limit := parsePagination(r)

	verifications, err := h.verifSvc.ListPending(page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if verifications == nil {
		verifications = []models.Verification{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": verifications, "page": page, "limit": limit,
	})
}

// Review handles PUT /api/v1/admin/verifications/:id.
func (h *VerificationHandler) Review(w http.ResponseWriter, r *http.Request) {
	adminID := middleware.GetUserID(r)
	verificationID := chi.URLParam(r, "id")

	var req models.ReviewVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	v, err := h.verifSvc.Review(verificationID, adminID, req)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "verification not found" {
			status = http.StatusNotFound
		}
		respondError(w, status, err.Error(), "REVIEW_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, v)
}
