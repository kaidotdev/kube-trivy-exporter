package middleware

import (
	"net/http"
	"runtime/debug"
)

func NewRecoverMiddleware(logger ILogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Printf("panic: %+v\n", err)
					debug.PrintStack()
					http.Error(w, http.StatusText(500), 500)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
