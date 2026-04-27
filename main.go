package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Created  time.Time `json:"created"`
}

type Session struct {
	Username string    `json:"username"`
	Expiry   time.Time `json:"expiry"`
}

var (
	users    = make(map[string]User)
	sessions = make(map[string]Session)
)

func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		name := r.FormValue("name")
		email := r.FormValue("email")
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm-password")
		terms := r.FormValue("terms")

		if name == "" || email == "" || username == "" || password == "" || confirmPassword == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		if password != confirmPassword {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		if terms != "on" && terms != "true" {
			http.Error(w, "You must agree to the Terms and Conditions", http.StatusBadRequest)
			return
		}

		for _, u := range users {
			if u.Email == email {
				http.Error(w, "Email already registered", http.StatusBadRequest)
				return
			}
			if u.Username == username {
				http.Error(w, "Username already taken", http.StatusBadRequest)
				return
			}
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		user := User{
			ID:       generateID(),
			Name:     name,
			Email:    email,
			Username: username,
			Password: string(hashedPassword),
			Created:  time.Now(),
		}

		users[user.ID] = user

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":  "Registration successful",
			"username": user.Username,
		})
	} else {
		http.Redirect(w, r, "/register.html", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		var foundUser User
		for _, u := range users {
			if u.Username == username {
				foundUser = u
				break
			}
		}

		if foundUser.ID == "" {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		sessionID := generateID()
		sessions[sessionID] = Session{
			Username: username,
			Expiry:   time.Now().Add(24 * time.Hour),
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			MaxAge:   86400,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":  "Login successful",
			"redirect": "/home.html",
		})
	} else {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
	}
}

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

	var user User
	for _, u := range users {
		if u.Username == session.Username {
			user = u
			break
		}
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
        <p><strong>Username:</strong> %s</p>
      </div>
    </div>
  </div>
  <footer>
    <p>&copy; %d Healthcare Unified System. All Rights Reserved</p>
  </footer>
</body>
</html>`, user.Username, user.Name, user.Email, user.Username, time.Now().Year())
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/home.html", homeHandler)

	fs := http.FileServer(http.Dir("template"))
	http.Handle("/", fs)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Printf("Server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
