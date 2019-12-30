package processor

import "k8s.io/client-go/kubernetes"

type IKubernetesClient interface {
	kubernetes.Interface
}

type ILogger interface {
	Error(format string, v ...interface{})
	Info(format string, v ...interface{})
	Debug(format string, v ...interface{})
}
