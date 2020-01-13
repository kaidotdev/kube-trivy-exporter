package middleware_test

import (
	"context"
	"fmt"
	"kube-trivy-exporter/pkg/client"
	"kube-trivy-exporter/pkg/server/middleware"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestClientClosedRequestMiddleware(t *testing.T) {
	tests := []struct {
		name     string
		receiver http.Handler
		in       *http.Request
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			middleware.NewClientClosedRequestMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			httptest.NewRequest("GET", "/", nil).WithContext(client.SetRequestLogger(context.Background(), client.NewRequestLogger("", loggerMock{}))),
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			middleware.NewClientClosedRequestMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			func() *http.Request {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return httptest.NewRequest("GET", "/", nil).WithContext(client.SetRequestLogger(ctx, client.NewRequestLogger("", loggerMock{
					fakeInfof: func(format string, v ...interface{}) {
						stack :=
							`client closed request in GET /:
    kube-trivy-exporter/pkg/server/middleware.NewClientClosedRequestMiddleware.func1.1.1
        kube-trivy-exporter@/pkg/server/middleware/client_closed_request.go:55
  - context canceled
`
						want := fmt.Sprintf(`{"severity":"info","requestID":"","payload":%q}`, stack)
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				})))
			}(),
		},
	}
	for _, tt := range tests {
		got := httptest.NewRecorder()

		name := tt.name
		receiver := tt.receiver
		in := tt.in
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			receiver.ServeHTTP(got, in)
		})
	}
}
