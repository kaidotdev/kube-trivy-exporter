package external_test

import (
	"context"
	"kube-trivy-exporter/pkg/adapter/external"
	"kube-trivy-exporter/pkg/domain"

	v1 "k8s.io/api/core/v1"
)

type kubernetesClientMock struct {
	external.IKubernetesClient
	fakeContainers func() ([]v1.Container, error)
}

func (k *kubernetesClientMock) Containers() ([]v1.Container, error) {
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
