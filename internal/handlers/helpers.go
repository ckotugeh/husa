package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// errorResponse is the standard error envelope.
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// respondJSON writes a JSON response with the given status code.
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

// respondError writes a standard JSON error response.
func respondError(w http.ResponseWriter, status int, message, code string) {
	respondJSON(w, status, errorResponse{Error: message, Code: code})
}

// parsePagination extracts page and limit query parameters with sensible defaults.
func parsePagination(r *http.Request) (page, limit int) {
	page = 1
	limit = 20

	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	return page, limit
}
