package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/husa/backend/internal/middleware"
	"github.com/husa/backend/internal/models"
	"github.com/husa/backend/internal/services"
)

// NotificationHandler handles notification endpoints.
type NotificationHandler struct {
	notifSvc *services.NotificationService
}

// NewNotificationHandler creates a new NotificationHandler.
func NewNotificationHandler(notifSvc *services.NotificationService) *NotificationHandler {
	return &NotificationHandler{notifSvc: notifSvc}
}

// List handles GET /api/v1/notifications.
func (h *NotificationHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	page, limit := parsePagination(r)

	notifs, err := h.notifSvc.List(userID, page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if notifs == nil {
		notifs = []models.Notification{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": notifs, "page": page, "limit": limit,
	})
}

// MarkRead handles PUT /api/v1/notifications/:id/read.
func (h *NotificationHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	notifID := chi.URLParam(r, "id")

	if err := h.notifSvc.MarkRead(notifID, userID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "MARK_READ_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "notification marked as read"})
}

// MarkAllRead handles PUT /api/v1/notifications/read-all.
func (h *NotificationHandler) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	if err := h.notifSvc.MarkAllRead(userID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "MARK_ALL_READ_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "all notifications marked as read"})
}
