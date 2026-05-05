package router

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/husa/backend/internal/config"
	"github.com/husa/backend/internal/handlers"
	"github.com/husa/backend/internal/middleware"
	"github.com/husa/backend/internal/services"
	"golang.org/x/time/rate"
)

// New builds and returns the fully configured chi router.
func New(db *sql.DB, cfg *config.Config) http.Handler {
	// --- Services ---
	authSvc := services.NewAuthService(db, cfg.JWTSecret, cfg.JWTExpiryHours, cfg.RefreshTokenExpiryDays)
	userSvc := services.NewUserService(db)
	caseSvc := services.NewCaseService(db)
	commentSvc := services.NewCommentService(db)
	msgSvc := services.NewMessageService(db)
	notifSvc := services.NewNotificationService(db)
	verifSvc := services.NewVerificationService(db)

	// --- Handlers ---
	authH := handlers.NewAuthHandler(authSvc)
	userH := handlers.NewUserHandler(userSvc)
	caseH := handlers.NewCaseHandler(caseSvc)
	commentH := handlers.NewCommentHandler(commentSvc)
	msgH := handlers.NewMessageHandler(msgSvc)
	notifH := handlers.NewNotificationHandler(notifSvc)
	verifH := handlers.NewVerificationHandler(verifSvc)
	searchH := handlers.NewSearchHandler(db)

	// --- Rate limiter: 20 req/s, burst 50 ---
	rl := middleware.NewRateLimiter(rate.Limit(20), 50)

	r := chi.NewRouter()

	// Global middleware stack.
	r.Use(chiMiddleware.Recoverer)
	r.Use(middleware.Logger)
	r.Use(corsMiddleware(cfg.AllowedOrigins))
	r.Use(rl.Limit)

	// Health check (no auth required).
	r.Get("/health", healthCheck(db))

	// API v1 routes.
	r.Route("/api/v1", func(r chi.Router) {
		// --- Auth (public) ---
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authH.Register)
			r.Post("/login", authH.Login)
			r.Post("/refresh", authH.Refresh)
			r.Post("/logout", authH.Logout)
		})

		// --- Users ---
		r.Route("/users", func(r chi.Router) {
			// Protected: own profile
			r.Group(func(r chi.Router) {
				r.Use(middleware.Authenticate(authSvc))
				r.Get("/me", userH.GetMe)
				r.Put("/me", userH.UpdateMe)
				r.Post("/{id}/follow", userH.Follow)
				r.Delete("/{id}/follow", userH.Unfollow)
			})
			// Public: other profiles
			r.Get("/{id}", userH.GetUser)
			r.Get("/{id}/followers", userH.ListFollowers)
			r.Get("/{id}/following", userH.ListFollowing)
		})

		// --- Verification ---
		r.Route("/verification", func(r chi.Router) {
			r.Use(middleware.Authenticate(authSvc))
			r.Post("/submit", verifH.Submit)
			r.Get("/status", verifH.GetStatus)
		})

		// --- Admin ---
		r.Route("/admin", func(r chi.Router) {
			r.Use(middleware.Authenticate(authSvc))
			r.Use(middleware.RequireRole("admin"))
			r.Get("/verifications", verifH.ListPending)
			r.Put("/verifications/{id}", verifH.Review)
		})

		// --- Cases ---
		r.Route("/cases", func(r chi.Router) {
			// Public reads
			r.Get("/", caseH.List)
			r.Get("/specialty/{tag}", caseH.ListBySpecialty)
			r.Get("/{id}", caseH.GetByID)
			r.Get("/{id}/comments", commentH.List)

			// Protected writes
			r.Group(func(r chi.Router) {
				r.Use(middleware.Authenticate(authSvc))
				r.Post("/", caseH.Create)
				r.Put("/{id}", caseH.Update)
				r.Delete("/{id}", caseH.Delete)
				r.Post("/{id}/comments", commentH.Create)
			})
		})

		// --- Comments (standalone delete) ---
		r.Route("/comments", func(r chi.Router) {
			r.Use(middleware.Authenticate(authSvc))
			r.Delete("/{id}", commentH.Delete)
		})

		// --- Messages ---
		r.Route("/messages", func(r chi.Router) {
			r.Use(middleware.Authenticate(authSvc))
			r.Post("/", msgH.Send)
			r.Get("/conversations", msgH.ListConversations)
			r.Get("/{userId}", msgH.GetConversation)
			r.Put("/{id}/read", msgH.MarkRead)
		})

		// --- Notifications ---
		r.Route("/notifications", func(r chi.Router) {
			r.Use(middleware.Authenticate(authSvc))
			r.Get("/", notifH.List)
			r.Put("/read-all", notifH.MarkAllRead)
			r.Put("/{id}/read", notifH.MarkRead)
		})

		// --- Search ---
		r.Get("/search", searchH.Search)
	})

	return r
}

// healthCheck returns a handler that reports server and database health.
func healthCheck(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbStatus := "ok"
		if err := db.Ping(); err != nil {
			dbStatus = "error"
		}
		status := http.StatusOK
		if dbStatus != "ok" {
			status = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(`{"status":"ok","db":"` + dbStatus + `"}`)) //nolint:errcheck
	}
}

// corsMiddleware adds CORS headers for the configured allowed origins.
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := false
			for _, o := range allowedOrigins {
				if strings.EqualFold(o, origin) {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
