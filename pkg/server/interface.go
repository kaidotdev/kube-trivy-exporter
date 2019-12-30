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
	Error(format string, v ...interface{})
	Info(format string, v ...interface{})
	Debug(format string, v ...interface{})
}
