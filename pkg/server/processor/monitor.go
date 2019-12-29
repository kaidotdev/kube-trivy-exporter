package processor

import (
	"context"
	"kube-trivy-exporter/pkg/client"
	"kube-trivy-exporter/pkg/server/collector"
	"net"
	"net/http"
	"net/http/pprof"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"contrib.go.opencensus.io/exporter/jaeger"
	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/trace"
	"golang.org/x/net/netutil"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const (
	metricsPath = "/metrics"
)

type MonitorSettings struct {
	Address               string
	MaxConnections        int64
	JaegerEndpoint        string
	EnableProfiling       bool
	EnableTracing         bool
	TracingSampleRate     float64
	KeepAlived            bool
	ReUsePort             bool
	TCPKeepAliveInterval  time.Duration
	TrivyConcurrency      int64
	CollectorLoopInterval time.Duration
	KubernetesClient      IKubernetesClient
	Logger                ILogger
}

type Monitor struct {
	maxConnections int64
	listener       net.Listener
	server         *http.Server
}

func NewMonitor(settings MonitorSettings) (*Monitor, error) {
	router := mux.NewRouter()

	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(collector.NewTrivyCollector(
		context.Background(),
		settings.Logger,
		&client.KubernetesClient{
			Inner: settings.KubernetesClient,
		},
		&client.TrivyClient{
			Executor: func(ctx context.Context, name string, arg ...string) ([]byte, error) {
				return exec.CommandContext(ctx, name, arg...).CombinedOutput()
			},
		},
		settings.TrivyConcurrency,
		settings.CollectorLoopInterval,
	))

	prometheusExporter, err := ocprom.NewExporter(ocprom.Options{Registry: registry})
	if err != nil {
		return nil, xerrors.Errorf("could not set up prometheus exporter: %w", err)
	}
	view.SetReportingPeriod(1 * time.Second)
	view.RegisterExporter(prometheusExporter)
	router.Handle(metricsPath, prometheusExporter)

	if settings.EnableTracing {
		jaegerExporter, err := jaeger.NewExporter(jaeger.Options{
			AgentEndpoint: settings.JaegerEndpoint,
			Process: jaeger.Process{
				ServiceName: "kube-trivy-exporter",
			},
		})
		if err != nil {
			return nil, xerrors.Errorf("could not set up jaeger exporter: %w", err)
		}
		defer jaegerExporter.Flush()

		trace.ApplyConfig(trace.Config{DefaultSampler: trace.ProbabilitySampler(settings.TracingSampleRate)})
		trace.RegisterExporter(jaegerExporter)
	}

	if settings.EnableProfiling {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
		router.HandleFunc("/debug/pprof/", pprof.Index)
		router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	var listener net.Listener
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
	return &Monitor{
		maxConnections: settings.MaxConnections,
		listener:       listener,
		server:         server,
	}, nil
}

func (m *Monitor) Start() error {
	return m.server.Serve(netutil.LimitListener(m.listener, int(m.maxConnections)))
}

func (m *Monitor) Stop(ctx context.Context) error {
	return m.server.Shutdown(ctx)
}
