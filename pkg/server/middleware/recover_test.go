package middleware_test

import (
	"errors"
	"fmt"
	"kube-trivy-exporter/pkg/server/middleware"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRecoverMiddleware(t *testing.T) {
	tests := []struct {
		receiver http.Handler
		in       *http.Request
	}{
		{
			middleware.NewRecoverMiddleware(
				loggerMock{},
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			httptest.NewRequest("GET", "/", nil),
		},
		{
			middleware.NewRecoverMiddleware(
				loggerMock{
					fakePrintf: func(format string, v ...interface{}) {
						want := "panic: fake\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic(errors.New("fake"))
			})),
			httptest.NewRequest("GET", "/", nil),
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
