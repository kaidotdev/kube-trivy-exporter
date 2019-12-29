package collector

import (
	"context"

	v1 "k8s.io/api/core/v1"
)

type ILogger interface {
	Printf(format string, v ...interface{})
	Fatalf(format string, v ...interface{})
}

type IKubernetesClient interface {
	Containers() ([]v1.Container, error)
}

type ITrivyClient interface {
	Do(context.Context, string) ([]byte, error)
}
