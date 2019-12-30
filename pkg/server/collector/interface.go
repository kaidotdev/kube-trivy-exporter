package collector

import (
	"context"

	v1 "k8s.io/api/core/v1"
)

type ILogger interface {
	Error(format string, v ...interface{})
	Info(format string, v ...interface{})
	Debug(format string, v ...interface{})
}

type IKubernetesClient interface {
	Containers() ([]v1.Container, error)
}

type ITrivyClient interface {
	Do(context.Context, string) ([]byte, error)
}
