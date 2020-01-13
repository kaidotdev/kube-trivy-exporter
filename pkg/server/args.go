package server

import "math"

type Args struct {
	APIAddress               string
	APIMaxConnections        int64
	MonitorAddress           string
	MonitorMaxConnections    int64
	MonitoringJaegerEndpoint string
	EnableProfiling          bool
	EnableTracing            bool
	TracingSampleRate        float64
	KeepAlived               bool
	ReUsePort                bool
	TCPKeepAliveInterval     int64
	TrivyConcurrency         int64
	CollectorLoopInterval    int64
	Verbose                  bool
}

func DefaultArgs() *Args {
	return &Args{
		APIAddress:               "127.0.0.1:8000",
		APIMaxConnections:        math.MaxInt64,
		MonitorAddress:           "127.0.0.1:9090",
		MonitorMaxConnections:    math.MaxInt64,
		MonitoringJaegerEndpoint: "jaeger-agent.istio-system.svc.cluster.local:6831",
		EnableProfiling:          false,
		EnableTracing:            false,
		TracingSampleRate:        0,
		KeepAlived:               true,
		ReUsePort:                false,
		TCPKeepAliveInterval:     0,
		TrivyConcurrency:         10,
		CollectorLoopInterval:    60,
		Verbose:                  true,
	}
}
