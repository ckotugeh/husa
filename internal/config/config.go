package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Port                   string
	DatabaseURL            string
	JWTSecret              string
	JWTExpiryHours         int
	RefreshTokenExpiryDays int
	AllowedOrigins         []string
	Environment            string
}

// Load reads configuration from a .env file (if present) and environment variables.
// Environment variables always take precedence over .env file values.
func Load() *Config {
	// Load .env file if it exists; ignore error if it doesn't (production uses real env vars).
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from environment")
	}

	jwtExpiry := getEnvInt("JWT_EXPIRY_HOURS", 24)
	refreshExpiry := getEnvInt("REFRESH_TOKEN_EXPIRY_DAYS", 7)

	originsRaw := getEnv("ALLOWED_ORIGINS", "http://localhost:3000")
	origins := strings.Split(originsRaw, ",")
	for i, o := range origins {
		origins[i] = strings.TrimSpace(o)
	}

	return &Config{
		Port:                   getEnv("PORT", "8080"),
		DatabaseURL:            getEnv("DATABASE_URL", "postgres://postgres:password@localhost:5432/husadb?sslmode=disable"),
		JWTSecret:              getEnv("JWT_SECRET", "change-me-in-production"),
		JWTExpiryHours:         jwtExpiry,
		RefreshTokenExpiryDays: refreshExpiry,
		AllowedOrigins:         origins,
		Environment:            getEnv("ENVIRONMENT", "development"),
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}
