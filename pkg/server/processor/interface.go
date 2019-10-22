package processor

import "k8s.io/client-go/kubernetes"

type IKubernetesClient interface {
	kubernetes.Interface
}

type ILogger interface {
	Printf(format string, v ...interface{})
	Fatalf(format string, v ...interface{})
}
