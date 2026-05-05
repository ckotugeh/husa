package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/husa/backend/internal/middleware"
	"github.com/husa/backend/internal/models"
	"github.com/husa/backend/internal/services"
)

// CaseHandler handles clinical case endpoints.
type CaseHandler struct {
	caseSvc *services.CaseService
}

// NewCaseHandler creates a new CaseHandler.
func NewCaseHandler(caseSvc *services.CaseService) *CaseHandler {
	return &CaseHandler{caseSvc: caseSvc}
}

// Create handles POST /api/v1/cases.
func (h *CaseHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	var req models.CreateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	c, err := h.caseSvc.Create(userID, req)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "CREATE_FAILED")
		return
	}
	respondJSON(w, http.StatusCreated, c)
}

// List handles GET /api/v1/cases.
func (h *CaseHandler) List(w http.ResponseWriter, r *http.Request) {
	page, limit := parsePagination(r)
	params := models.CaseListParams{Page: page, Limit: limit}

	cases, err := h.caseSvc.List(params)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if cases == nil {
		cases = []models.Case{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": cases, "page": page, "limit": limit,
	})
}

// GetByID handles GET /api/v1/cases/:id.
func (h *CaseHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := h.caseSvc.GetByID(id)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error(), "CASE_NOT_FOUND")
		return
	}
	respondJSON(w, http.StatusOK, c)
}

// Update handles PUT /api/v1/cases/:id.
func (h *CaseHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	caseID := chi.URLParam(r, "id")

	var req models.UpdateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	c, err := h.caseSvc.Update(caseID, userID, req)
	if err != nil {
		status := http.StatusInternalServerError
		code := "UPDATE_FAILED"
		if err.Error() == "forbidden: not the case owner" {
			status = http.StatusForbidden
			code = "FORBIDDEN"
		} else if err.Error() == "case not found" {
			status = http.StatusNotFound
			code = "CASE_NOT_FOUND"
		}
		respondError(w, status, err.Error(), code)
		return
	}
	respondJSON(w, http.StatusOK, c)
}

// Delete handles DELETE /api/v1/cases/:id.
func (h *CaseHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	caseID := chi.URLParam(r, "id")

	if err := h.caseSvc.Delete(caseID, userID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "DELETE_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "case deleted"})
}

// ListBySpecialty handles GET /api/v1/cases/specialty/:tag.
func (h *CaseHandler) ListBySpecialty(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	page, limit := parsePagination(r)

	params := models.CaseListParams{Page: page, Limit: limit, SpecialtyTag: tag}
	cases, err := h.caseSvc.List(params)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if cases == nil {
		cases = []models.Case{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": cases, "page": page, "limit": limit, "specialty": tag,
	})
}
