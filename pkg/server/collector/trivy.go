package collector

import (
	"context"
	"kube-trivy-exporter/pkg/domain"
	"runtime/debug"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "trivy"
)

type ITrivyResponseAdapter interface {
	Request(context.Context) ([]domain.TrivyResponse, error)
}

type TrivyCollector struct {
	logger          ILogger
	adapter         ITrivyResponseAdapter
	loopInterval    time.Duration
	vulnerabilities *prometheus.GaugeVec
	cancelFunc      context.CancelFunc
}

func NewTrivyCollector(
	ctx context.Context,
	logger ILogger,
	adapter ITrivyResponseAdapter,
	loopInterval time.Duration,
) *TrivyCollector {
	ctx, cancel := context.WithCancel(ctx)

	collector := &TrivyCollector{
		logger:       logger,
		adapter:      adapter,
		loopInterval: loopInterval,
		vulnerabilities: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "vulnerabilities",
			Help:      "Vulnerabilities detected by trivy",
		}, []string{"target", "vulnerabilityId", "pkgName", "installedVersion", "severity"}),
		cancelFunc: cancel,
	}

	collector.startLoop(ctx)

	return collector
}

func (c *TrivyCollector) startLoop(ctx context.Context) {
	go func(ctx context.Context) {
		defer func() {
			if err := recover(); err != nil {
				c.logger.Printf("panic: %+v\n", err)
				debug.PrintStack()
			}
		}()

		t := time.NewTicker(c.loopInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				trivyResponses, err := c.adapter.Request(ctx)
				if err != nil {
					c.logger.Printf("Failed to collect metrics: %s\n", err.Error())
					continue
				}
				c.vulnerabilities.Reset()
				for _, trivyResponse := range trivyResponses {
					for _, vulnerability := range trivyResponse.Vulnerabilities {
						labels := []string{
							trivyResponse.Target,
							vulnerability.VulnerabilityID,
							vulnerability.PkgName,
							vulnerability.InstalledVersion,
							vulnerability.Severity,
						}
						c.vulnerabilities.WithLabelValues(labels...).Set(1)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}(ctx)
}

func (c *TrivyCollector) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		c.vulnerabilities,
	}
}

func (c *TrivyCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range c.collectors() {
		collector.Describe(ch)
	}
}

func (c *TrivyCollector) Collect(ch chan<- prometheus.Metric) {
	for _, collector := range c.collectors() {
		collector.Collect(ch)
	}
}

func (c *TrivyCollector) Cancel() {
	c.cancelFunc()
}
