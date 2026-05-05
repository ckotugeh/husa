package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/husa/backend/internal/middleware"
	"github.com/husa/backend/internal/models"
	"github.com/husa/backend/internal/services"
)

// MessageHandler handles direct messaging endpoints.
type MessageHandler struct {
	msgSvc *services.MessageService
}

// NewMessageHandler creates a new MessageHandler.
func NewMessageHandler(msgSvc *services.MessageService) *MessageHandler {
	return &MessageHandler{msgSvc: msgSvc}
}

// Send handles POST /api/v1/messages.
func (h *MessageHandler) Send(w http.ResponseWriter, r *http.Request) {
	senderID := middleware.GetUserID(r)

	var req models.SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	msg, err := h.msgSvc.Send(senderID, req)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "SEND_FAILED")
		return
	}
	respondJSON(w, http.StatusCreated, msg)
}

// ListConversations handles GET /api/v1/messages/conversations.
func (h *MessageHandler) ListConversations(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	convs, err := h.msgSvc.ListConversations(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if convs == nil {
		convs = []models.Conversation{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"data": convs})
}

// GetConversation handles GET /api/v1/messages/:userId.
func (h *MessageHandler) GetConversation(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	peerID := chi.URLParam(r, "userId")
	page, limit := parsePagination(r)

	msgs, err := h.msgSvc.GetConversation(userID, peerID, page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error(), "FETCH_FAILED")
		return
	}
	if msgs == nil {
		msgs = []models.Message{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data": msgs, "page": page, "limit": limit,
	})
}

// MarkRead handles PUT /api/v1/messages/:id/read.
func (h *MessageHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	messageID := chi.URLParam(r, "id")

	if err := h.msgSvc.MarkRead(messageID, userID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), "MARK_READ_FAILED")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "marked as read"})
}
