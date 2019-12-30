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
					logger.Error("panic: %+v\n", err)
					logger.Debug("%s\n", debug.Stack())
					http.Error(w, http.StatusText(500), 500)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
