package middleware

import (
	"context"
	"fmt"
	"kube-trivy-exporter/pkg/client"
	"net/http"
	"net/url"

	"golang.org/x/xerrors"
)

type ClientClosedRequestError struct {
	Method string
	URL    *url.URL
	Header http.Header
	Err    error
	frame  xerrors.Frame
}

func NewClientClosedRequestError(r *http.Request, err error) *ClientClosedRequestError {
	return &ClientClosedRequestError{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		Err:    err,
		frame:  xerrors.Caller(1),
	}
}

func (e *ClientClosedRequestError) Error() string {
	return fmt.Sprintf("client closed request in %s %s", e.Method, e.URL.String())
}

func (e *ClientClosedRequestError) Unwrap() error {
	return e.Err
}

func (e *ClientClosedRequestError) Format(f fmt.State, c rune) {
	xerrors.FormatError(e, f, c)
}

func (e *ClientClosedRequestError) FormatError(p xerrors.Printer) error {
	p.Print(e.Error())
	e.frame.Format(p)
	return e.Err
}

func NewClientClosedRequestMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := r.Context().Err(); err == context.Canceled {
					logger := client.GetRequestLogger(r.Context())
					logger.Infof("%+v\n", NewClientClosedRequestError(r, err))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
