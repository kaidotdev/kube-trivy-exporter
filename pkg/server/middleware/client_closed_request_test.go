package middleware_test

import (
	"context"
	"fmt"
	"kube-trivy-exporter/pkg/server/middleware"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestClientClosedRequestMiddleware(t *testing.T) {
	tests := []struct {
		receiver http.Handler
		in       *http.Request
	}{
		{
			middleware.NewClientClosedRequestMiddleware(
				loggerMock{},
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			httptest.NewRequest("GET", "/", nil),
		},
		{
			middleware.NewClientClosedRequestMiddleware(
				loggerMock{
					fakePrintf: func(format string, v ...interface{}) {
						want := "Client Closed Request\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			func() *http.Request {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return httptest.NewRequest("GET", "/", nil).WithContext(ctx)
			}(),
		},
	}
	for _, tt := range tests {
		got := httptest.NewRecorder()

		receiver := tt.receiver
		in := tt.in
		t.Run(fmt.Sprintf("%#v/%#v", receiver, in), func(t *testing.T) {
			t.Parallel()

			receiver.ServeHTTP(got, in)
		})
	}
}
