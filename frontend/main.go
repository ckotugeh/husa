package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// Backend API URL - can be configured via environment variable
var backendURL *url.URL

// Session stores user session data
type Session struct {
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	FullName     string    `json:"full_name"`
	Expiry       time.Time `json:"expiry"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
}

var sessions = make(map[string]Session)

func getBackendURL() *url.URL {
	backendURLStr := os.Getenv("BACKEND_URL")
	if backendURLStr == "" {
		backendURLStr = "http://localhost:8080"
	}

	u, err := url.Parse(backendURLStr)
	if err != nil {
		log.Fatalf("Invalid BACKEND_URL: %v", err)
	}
	return u
}

// proxyHandler creates a reverse proxy to the backend
func proxyHandler(backend *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(backend)

	// Use Director to modify the request
	proxy.Director = func(req *http.Request) {
		originalPath := req.URL.Path
		originalRawQuery := req.URL.RawQuery
		
		req.URL.Scheme = backend.Scheme
		req.URL.Host = backend.Host
		req.URL.Path = singleJoiningSlash(backend.Path, originalPath)
		req.URL.RawQuery = originalRawQuery
		req.Host = backend.Host

		// Forward cookies for session
		cookie, err := req.Cookie("session_id")
		if err == nil {
			session, exists := sessions[cookie.Value]
			if exists && time.Now().Before(session.Expiry) {
				// Add Authorization header with access token
				req.Header.Set("Authorization", "Bearer "+session.AccessToken)
			}
		}
	}

	// Modify the response to handle errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Backend service unavailable", http.StatusServiceUnavailable)
	}

	return proxy
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// authProxyHandler handles auth endpoints with session management
func authProxyHandler(backend *url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create a proxy request
		proxyReq, err := http.NewRequest(r.Method, backend.String()+r.URL.Path, r.Body)
		if err != nil {
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}

		// Copy headers
		for key, values := range r.Header {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}

		// Set content type for form data
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			proxyReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		}

		// Send request to backend
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(proxyReq)
		if err != nil {
			log.Printf("Backend request error: %v", err)
			http.Error(w, "Backend service unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		// Read response body
		var respBody map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&respBody); err == nil {
			// Handle successful auth responses
			if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/auth/register" {
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
					// Create session
					sessionID := generateSessionID()

					// Extract user and tokens from response
					if user, ok := respBody["user"].(map[string]interface{}); ok {
						if tokens, ok := respBody["tokens"].(map[string]interface{}); ok {
							accessToken, _ := tokens["access_token"].(string)
							refreshToken, _ := tokens["refresh_token"].(string)
							userID, _ := user["id"].(string)
							email, _ := user["email"].(string)
							fullName, _ := user["full_name"].(string)

							sessions[sessionID] = Session{
								UserID:       userID,
								Email:        email,
								FullName:     fullName,
								Expiry:       time.Now().Add(24 * time.Hour),
								AccessToken:  accessToken,
								RefreshToken: refreshToken,
							}

							// Set session cookie
							http.SetCookie(w, &http.Cookie{
								Name:     "session_id",
								Value:    sessionID,
								Path:     "/",
								HttpOnly: true,
								Secure:   false,
								MaxAge:   86400,
							})
						}
					}
				}
			}

			// Return the response
			w.WriteHeader(resp.StatusCode)
			json.NewEncoder(w).Encode(respBody)
		} else {
			// For non-JSON responses, just copy the status
			w.WriteHeader(resp.StatusCode)
		}
	}
}

func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// homeHandler serves the home page with user info
func homeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	session, exists := sessions[cookie.Value]
	if !exists || time.Now().After(session.Expiry) {
		delete(sessions, cookie.Value)
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Home - Healthcare Unified System</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <nav class="navbar">
    <div class="nav-container">
      <a href="/home.html" class="nav-logo">HUSA</a>
      <div class="nav-menu">
        <a href="/home.html" class="nav-link">Home</a>
        <a href="/logout" class="nav-link">Logout</a>
      </div>
    </div>
  </nav>
  <div class="hero">
    <div class="hero-content">
      <h1>Welcome, %s!</h1>
      <p class="hero-subtitle">Healthcare Unified System</p>
      <div class="user-info">
        <p><strong>Name:</strong> %s</p>
        <p><strong>Email:</strong> %s</p>
      </div>
    </div>
  </div>
  <footer>
    <p>&copy; %d Healthcare Unified System. All Rights Reserved</p>
  </footer>
</body>
</html>`, session.FullName, session.FullName, session.Email, time.Now().Year())
}

// logoutHandler clears the session
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		delete(sessions, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/index.html", http.StatusSeeOther)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	backendURL = getBackendURL()
	log.Printf("Connecting to backend at: %s", backendURL)

	// API proxy - forwards all /api/* requests to backend
	http.Handle("/api/", http.StripPrefix("/api", proxyHandler(backendURL)))

	// Auth endpoints with session management
	http.HandleFunc("/api/v1/auth/login", authProxyHandler(backendURL))
	http.HandleFunc("/api/v1/auth/register", authProxyHandler(backendURL))
	http.HandleFunc("/api/v1/auth/refresh", authProxyHandler(backendURL))
	http.HandleFunc("/api/v1/auth/logout", authProxyHandler(backendURL))

	// Page handlers
	http.HandleFunc("/home.html", homeHandler)
	http.HandleFunc("/logout", logoutHandler)

	// Static files
	fs := http.FileServer(http.Dir("template"))
	http.Handle("/", fs)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Printf("Frontend server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
