package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/husa/backend/internal/middleware"
	"github.com/husa/backend/internal/models"
	"github.com/husa/backend/internal/services"
)

// CommentHandler handles comment endpoints.
type CommentHandler struct {
	commentSvc *services.CommentService
}

// NewCommentHandler creates a new CommentHandler.
func NewCommentHandler(commentSvc *services.CommentService) *CommentHandler {
	return &CommentHandler{commentSvc: commentSvc}
}

// Create handles POST /api/v1/cases/:id/comments.
func (h *CommentHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	caseID := chi.URLParam(r, "id")

	var req models.CreateCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	comment, err := h.commentSvc.Create(caseID, userID, req)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "case not found" {
			status = http.StatusNotFound
		}
		respondError(w, status, err.Error(), "CREATE_FAILED")
		return
	}
	respondJSON(w, http.StatusCreated, comment)
}

// List handles GET /api/v1/cases/:id/comments.
func (h *CommentHandler) List(w http.ResponseWriter, r *http.Request) {
	caseID := chi.URLParam(r, "id")
	page, limit := parsePagination(r)

	comments, err := h.commentSvc.ListByCaseID(caseID, page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if comments == nil {
		comments = []models.Comment{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": comments, "page": page, "limit": limit,
	})
}

// Delete handles DELETE /api/v1/comments/:id.
func (h *CommentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	commentID := chi.URLParam(r, "id")

	if err := h.commentSvc.Delete(commentID, userID); err != nil {
		status := http.StatusBadRequest
		code := "DELETE_FAILED"
		if err.Error() == "comment not found" {
			status = http.StatusNotFound
			code = "NOT_FOUND"
		} else if err.Error() == "forbidden: not the comment owner" {
			status = http.StatusForbidden
			code = "FORBIDDEN"
		}
		respondError(w, status, err.Error(), code)
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "comment deleted"})
}
