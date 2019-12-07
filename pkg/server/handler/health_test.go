package handler_test

import (
	"bytes"
	"fmt"
	"kube-trivy-exporter/pkg/server/handler"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestHealthHandler(t *testing.T) {
	tests := []struct {
		name         string
		receiver     *handler.HealthHandler
		in           *http.Request
		want         *httptest.ResponseRecorder
		optsFunction func(interface{}) cmp.Option
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			handler.NewHealthHandler(),
			httptest.NewRequest("GET", "/health", nil),
			&httptest.ResponseRecorder{
				Code:      http.StatusOK,
				HeaderMap: http.Header{"Content-Type": {"text/plain"}},
				Body:      bytes.NewBuffer([]byte("OK")),
			},
			func(got interface{}) cmp.Option {
				switch v := got.(type) {
				case *httptest.ResponseRecorder:
					return cmp.Options{
						cmpopts.IgnoreUnexported(*v),
						cmp.AllowUnexported(*v.Body),
					}
				default:
					return nil
				}
			},
		},
	}
	for _, tt := range tests {
		got := httptest.NewRecorder()

		name := tt.name
		receiver := tt.receiver
		in := tt.in
		want := tt.want
		optsFunction := tt.optsFunction
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			receiver.ServeHTTP(got, in)
			if diff := cmp.Diff(want, got, optsFunction(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}
