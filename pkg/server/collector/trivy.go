package collector

import (
	"context"
	"encoding/json"
	"kube-trivy-exporter/pkg/client"
	"runtime/debug"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
)

const (
	namespace = "trivy"
)

type ITrivyResponseAdapter interface {
	Request(context.Context) ([]client.TrivyResponse, error)
}

type TrivyCollector struct {
	logger           ILogger
	kubernetesClient IKubernetesClient
	trivyClient      ITrivyClient
	concurrency      int64
	loopInterval     time.Duration
	vulnerabilities  *prometheus.GaugeVec
	cancelFunc       context.CancelFunc
}

func NewTrivyCollector(
	ctx context.Context,
	logger ILogger,
	kubernetesClient IKubernetesClient,
	trivyClient ITrivyClient,
	concurrency int64,
	loopInterval time.Duration,
) *TrivyCollector {
	ctx, cancel := context.WithCancel(ctx)

	collector := &TrivyCollector{
		logger:           logger,
		kubernetesClient: kubernetesClient,
		trivyClient:      trivyClient,
		concurrency:      concurrency,
		loopInterval:     loopInterval,
		vulnerabilities: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "vulnerabilities",
			Help:      "Vulnerabilities detected by trivy",
		}, []string{"image", "vulnerabilityId", "pkgName", "installedVersion", "severity"}),
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
				containers, err := c.kubernetesClient.Containers()
				if err != nil {
					c.logger.Printf("Failed to get containers: %s\n", err.Error())
					continue
				}

				semaphore := make(chan struct{}, c.concurrency)
				defer close(semaphore)

				wg := sync.WaitGroup{}
				mutex := &sync.Mutex{}

				var trivyResponses []client.TrivyResponse
				for _, container := range containers {
					wg.Add(1)
					go func(container v1.Container) {
						defer wg.Done()
						defer func() {
							if err := recover(); err != nil {
								c.logger.Printf("panic: %+v\n", err)
								debug.PrintStack()
							}
						}()

						semaphore <- struct{}{}
						defer func() {
							<-semaphore
						}()
						out, err := c.trivyClient.Do(ctx, container.Image)
						if err != nil {
							c.logger.Printf("Failed to detect vulnerability at %s: %s\n", container.Image, err.Error())
							return
						}

						var responses []client.TrivyResponse
						if err := json.Unmarshal(out, &responses); err != nil {
							c.logger.Printf("Failed to parse trivy response at %s: %s\n", container.Image, err.Error())
							return
						}
						func() {
							mutex.Lock()
							defer mutex.Unlock()
							trivyResponses = append(trivyResponses, responses...)
						}()
					}(container)
				}
				wg.Wait()

				c.vulnerabilities.Reset()
				for _, trivyResponse := range trivyResponses {
					for _, vulnerability := range trivyResponse.Vulnerabilities {
						labels := []string{
							trivyResponse.ExtractImage(),
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
