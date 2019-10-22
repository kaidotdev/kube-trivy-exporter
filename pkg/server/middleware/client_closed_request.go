package middleware

import (
	"context"
	"net/http"
)

func NewClientClosedRequestMiddleware(logger ILogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if r.Context().Err() == context.Canceled {
					logger.Printf("Client Closed Request\n")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
