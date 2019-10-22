package server

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

type IProcessor interface {
	Start() error
	Stop(context.Context) error
}

type IKubernetesClient interface {
	kubernetes.Interface
}

type ILogger interface {
	Printf(format string, v ...interface{})
	Fatalf(format string, v ...interface{})
}
