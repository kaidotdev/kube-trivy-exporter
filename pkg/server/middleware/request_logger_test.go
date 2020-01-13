package middleware_test

import (
	"fmt"
	"kube-trivy-exporter/pkg/client"
	"kube-trivy-exporter/pkg/server/middleware"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRequestLoggerMiddleware(t *testing.T) {
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
			middleware.NewRequestLoggerMiddleware(loggerMock{
				fakeErrorf: func(format string, v ...interface{}) {
					want := `{"severity":"error","requestID":"fake2","payload":"fake1"}`
					got := fmt.Sprintf(format, v...)
					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("(-want +got):\n%s", diff)
					}
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				client.GetRequestLogger(r.Context()).Errorf("fake1")
			})),
			func() *http.Request {
				request := httptest.NewRequest("GET", "/", nil)
				request.Header.Set("x-request-id", "fake2")
				return request
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
