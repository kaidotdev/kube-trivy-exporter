package server

import (
	"context"
	"kube-trivy-exporter/pkg/client"
	"net/http"
	"runtime/debug"
	"time"
)

const (
	gracePeriod = 10
)

type Instance struct {
	processors       []IProcessor
	kubernetesClient IKubernetesClient
	logger           ILogger
}

func NewInstance() *Instance {
	return &Instance{
		logger: client.NewDefaultLogger(),
	}
}

func (i *Instance) KubernetesClient() IKubernetesClient {
	return i.kubernetesClient
}

func (i *Instance) SetKubernetesClient(kubernetesClient IKubernetesClient) {
	i.kubernetesClient = kubernetesClient
}

func (i *Instance) Logger() ILogger {
	return i.logger
}

func (i *Instance) SetLogger(logger ILogger) {
	i.logger = logger
}

func (i *Instance) AddProcessor(processor IProcessor) {
	i.processors = append(i.processors, processor)
}

func (i *Instance) Start() {
	for _, processor := range i.processors {
		go func(processor IProcessor) {
			defer func() {
				if err := recover(); err != nil {
					i.logger.Errorf("panic: %+v\n", err)
					i.logger.Debugf("%s\n", debug.Stack())
				}
			}()
			if err := processor.Start(); err != nil && err != http.ErrServerClosed {
				i.logger.Errorf("Failed to listen: %s\n", err)
			}
		}(processor)
	}
}

func (i *Instance) Shutdown(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(gracePeriod)*time.Second)
	defer cancel()
	for _, p := range i.processors {
		if err := p.Stop(ctx); err != nil {
			i.logger.Errorf("Failed to shutdown: %+v\n", err)
		}
	}
	select {
	case <-ctx.Done():
		i.logger.Infof("Instance shutdown timed out in %d seconds\n", gracePeriod)
	default:
	}
	i.logger.Infof("Instance has been shutdown\n")
}
