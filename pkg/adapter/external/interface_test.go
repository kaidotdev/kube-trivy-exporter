package external_test

import (
	"context"
	"kube-trivy-exporter/pkg/adapter/external"

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
	fakeDo func(context.Context, string) ([]byte, error)
}

func (t *trivyClientMock) Do(ctx context.Context, image string) ([]byte, error) {
	return t.fakeDo(ctx, image)
}

type loggerMock struct {
	external.ILogger
	fakePrintf func(format string, v ...interface{})
}

func (l loggerMock) Printf(format string, v ...interface{}) {
	l.fakePrintf(format, v...)
}
