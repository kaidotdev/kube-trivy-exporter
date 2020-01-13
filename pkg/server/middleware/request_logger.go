package middleware

import (
	"kube-trivy-exporter/pkg/client"
	"net/http"
)

func NewRequestLoggerMiddleware(logger ILogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestLogger := client.NewRequestLogger(r.Header.Get("x-request-id"), logger)
			ctx := client.SetRequestLogger(r.Context(), requestLogger)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
