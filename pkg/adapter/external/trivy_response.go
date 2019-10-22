package external

import (
	"context"
	"kube-trivy-exporter/pkg/domain"
	"runtime/debug"
	"sync"

	"golang.org/x/xerrors"
)

type TrivyResponseAdapter struct {
	logger           ILogger
	kubernetesClient IKubernetesClient
	trivyClient      ITrivyClient
	concurrency      int64
}

func NewTrivyResponseAdapter(
	logger ILogger,
	kubernetesClient IKubernetesClient,
	trivyClient ITrivyClient,
	concurrency int64,
) *TrivyResponseAdapter {
	return &TrivyResponseAdapter{
		logger:           logger,
		kubernetesClient: kubernetesClient,
		trivyClient:      trivyClient,
		concurrency:      concurrency,
	}
}

func (c *TrivyResponseAdapter) Request(
	ctx context.Context,
) ([]domain.TrivyResponse, error) {
	containers, err := c.kubernetesClient.Containers()
	if err != nil {
		return nil, xerrors.Errorf("could not get containers: %w", err)
	}

	semaphore := make(chan struct{}, c.concurrency)
	defer close(semaphore)

	wg := sync.WaitGroup{}
	mutex := &sync.Mutex{}

	var retval []domain.TrivyResponse
	for _, container := range containers {
		wg.Add(1)
		go func(container domain.KubernetesContainer) {
			defer wg.Done()
			defer func() {
				if err := recover(); err != nil {
					c.logger.Printf("panic: %+v\n", err)
					debug.PrintStack()
				}
			}()

			semaphore <- struct{}{}
			trivyResponses, err := c.trivyClient.Do(ctx, container.Image)
			if err != nil {
				c.logger.Printf("Failed to detect vulnerability at %s: %s\n", container.Image, err.Error())
			}
			func() {
				mutex.Lock()
				defer mutex.Unlock()
				retval = append(retval, trivyResponses...)
			}()

			<-semaphore
		}(container)
	}
	wg.Wait()
	return retval, nil
}
