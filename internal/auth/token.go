package auth

import (
	"net/http"
	"strings"
)

func RequireBearer(expectedToken string, next http.HandlerFunc) http.HandlerFunc {
	expectedToken = strings.TrimSpace(expectedToken)
	if expectedToken == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if authz == "" || !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimSpace(authz[len("Bearer "):])
		if provided != expectedToken {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

