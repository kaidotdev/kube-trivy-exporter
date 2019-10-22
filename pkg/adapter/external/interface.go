package external

import (
	"context"
	"kube-trivy-exporter/pkg/domain"
)

type IKubernetesClient interface {
	Containers() ([]domain.KubernetesContainer, error)
}

type ITrivyClient interface {
	Do(context.Context, string) ([]domain.TrivyResponse, error)
}

type ILogger interface {
	Printf(format string, v ...interface{})
	Fatalf(format string, v ...interface{})
}
