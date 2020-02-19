package collector

import (
	"context"

	v1 "k8s.io/api/core/v1"
)

type ILogger interface {
	Errorf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

type IKubernetesClient interface {
	Containers() ([]v1.Container, error)
}

type ITrivyClient interface {
	Do(context.Context, string) ([]byte, error)
	UpdateDatabase(context.Context) ([]byte, error)
	ClearCache(context.Context) ([]byte, error)
}
