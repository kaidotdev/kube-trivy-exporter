package external_test

import (
	"context"
	"kube-trivy-exporter/pkg/adapter/external"
	"kube-trivy-exporter/pkg/domain"
)

type kubernetesClientMock struct {
	external.IKubernetesClient
	fakeContainers func() ([]domain.KubernetesContainer, error)
}

func (k *kubernetesClientMock) Containers() ([]domain.KubernetesContainer, error) {
	return k.fakeContainers()
}

type trivyClientMock struct {
	external.ITrivyClient
	fakeDo func(context.Context, string) ([]domain.TrivyResponse, error)
}

func (t *trivyClientMock) Do(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
	return t.fakeDo(ctx, image)
}

type loggerMock struct {
	external.ILogger
	fakePrintf func(format string, v ...interface{})
}

func (l loggerMock) Printf(format string, v ...interface{}) {
	l.fakePrintf(format, v...)
}
