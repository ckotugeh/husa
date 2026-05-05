package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/husa/backend/internal/services"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const (
	// ContextUserID is the context key for the authenticated user's UUID.
	ContextUserID contextKey = "userID"
	// ContextUserRole is the context key for the authenticated user's role.
	ContextUserRole contextKey = "userRole"
)

// Authenticate is a middleware that validates a Bearer JWT and injects the
// user ID and role into the request context. It returns 401 if the token is
// missing or invalid.
func Authenticate(authSvc *services.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondUnauthorized(w, "missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				respondUnauthorized(w, "invalid authorization header format")
				return
			}

			userID, role, err := authSvc.ValidateAccessToken(parts[1])
			if err != nil {
				respondUnauthorized(w, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), ContextUserID, userID)
			ctx = context.WithValue(ctx, ContextUserRole, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns a middleware that allows only users with the given role.
// Must be used after Authenticate.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(ContextUserRole).(string)
			if !ok || userRole != role {
				respondForbidden(w, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserID extracts the authenticated user ID from the request context.
func GetUserID(r *http.Request) string {
	id, _ := r.Context().Value(ContextUserID).(string)
	return id
}

// GetUserRole extracts the authenticated user role from the request context.
func GetUserRole(r *http.Request) string {
	role, _ := r.Context().Value(ContextUserRole).(string)
	return role
}

func respondUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"` + msg + `","code":"UNAUTHORIZED"}`)) //nolint:errcheck
}

func respondForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"` + msg + `","code":"FORBIDDEN"}`)) //nolint:errcheck
}
