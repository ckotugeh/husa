package middleware

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// ipLimiter holds a per-IP token bucket limiter.
type ipLimiter struct {
	limiter *rate.Limiter
}

// RateLimiter holds the per-IP limiter map and configuration.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipLimiter
	r        rate.Limit // requests per second
	b        int        // burst size
}

// NewRateLimiter creates a RateLimiter with the given rate (req/s) and burst.
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*ipLimiter),
		r:        r,
		b:        b,
	}
}

// getLimiter returns (or creates) the limiter for the given IP address.
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if l, ok := rl.limiters[ip]; ok {
		return l.limiter
	}

	l := &ipLimiter{limiter: rate.NewLimiter(rl.r, rl.b)}
	rl.limiters[ip] = l
	return l.limiter
}

// Limit is the chi-compatible middleware function.
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Strip port if present.
		if idx := len(ip) - 1; idx >= 0 {
			for i := len(ip) - 1; i >= 0; i-- {
				if ip[i] == ':' {
					ip = ip[:i]
					break
				}
			}
		}

		if !rl.getLimiter(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded","code":"RATE_LIMITED"}`)) //nolint:errcheck
			return
		}
		next.ServeHTTP(w, r)
	})
}
