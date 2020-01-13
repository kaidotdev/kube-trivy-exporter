package processor

import "k8s.io/client-go/kubernetes"

type IKubernetesClient interface {
	kubernetes.Interface
}

type ILogger interface {
	Errorf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}
