package processor

import (
	"context"
	"kube-trivy-exporter/pkg/server/handler"
	"kube-trivy-exporter/pkg/server/middleware"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"go.opencensus.io/plugin/ochttp"
	"golang.org/x/net/netutil"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

type APISettings struct {
	Address              string
	MaxConnections       int64
	KeepAlived           bool
	ReUsePort            bool
	TCPKeepAliveInterval time.Duration
	Logger               ILogger
}

type API struct {
	maxConnections int64
	listener       net.Listener
	server         *http.Server
}

func NewAPI(settings APISettings) (*API, error) {
	router := mux.NewRouter()
	router.Use(middleware.NewRequestLoggerMiddleware(settings.Logger))
	router.Use(middleware.NewRecoverMiddleware())
	router.Use(middleware.NewClientClosedRequestMiddleware())

	router.Handle(
		"/health",
		handler.NewHealthHandler(),
	).Methods("GET")

	var listener net.Listener
	var err error
	if settings.ReUsePort {
		listenConfig := &net.ListenConfig{
			Control: func(network string, address string, c syscall.RawConn) error {
				var innerErr error
				if err := c.Control(func(s uintptr) {
					innerErr = unix.SetsockoptInt(int(s), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				}); err != nil {
					return err
				}
				if innerErr != nil {
					return innerErr
				}
				return nil
			},
			KeepAlive: settings.TCPKeepAliveInterval,
		}
		listener, err = listenConfig.Listen(context.Background(), "tcp", settings.Address)
	} else {
		listener, err = net.Listen("tcp", settings.Address)
	}
	if err != nil {
		return nil, xerrors.Errorf("could not listen %s: %w", settings.Address, err)
	}
	server := &http.Server{
		Handler: &ochttp.Handler{
			Handler: router,
			FormatSpanName: func(r *http.Request) string {
				return r.Method + " " + r.URL.Path
			},
		},
	}
	server.SetKeepAlivesEnabled(settings.KeepAlived)
	return &API{
		maxConnections: settings.MaxConnections,
		listener:       listener,
		server:         server,
	}, nil
}

func (a *API) Start() error {
	return a.server.Serve(netutil.LimitListener(a.listener, int(a.maxConnections)))
}

func (a *API) Stop(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}
