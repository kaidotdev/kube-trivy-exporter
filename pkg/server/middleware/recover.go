package middleware

import (
	"kube-trivy-exporter/pkg/client"
	"net/http"
	"runtime/debug"
)

func NewRecoverMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger := client.GetRequestLogger(r.Context())
					logger.Errorf("panic: %+v\n", err)
					logger.Debugf("%s\n", debug.Stack())
					http.Error(w, http.StatusText(500), 500)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
