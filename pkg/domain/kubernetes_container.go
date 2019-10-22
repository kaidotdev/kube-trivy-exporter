package domain

import v1 "k8s.io/api/core/v1"

type KubernetesContainer struct {
	v1.Container
}
