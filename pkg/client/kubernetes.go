package client

import (
	"kube-trivy-exporter/pkg/domain"

	"golang.org/x/xerrors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubernetesClient struct {
	Inner kubernetes.Interface
}

func (c *KubernetesClient) Containers() ([]domain.KubernetesContainer, error) {
	var containers []domain.KubernetesContainer

	deployments, err := c.Inner.AppsV1().Deployments("").List(metaV1.ListOptions{})
	if err != nil {
		return nil, xerrors.Errorf("could not get deployment: %w", err)
	}
	for _, deployment := range deployments.Items {
		for _, container := range deployment.Spec.Template.Spec.Containers {
			containers = append(containers, domain.KubernetesContainer{Container: container})
		}
	}

	statefulSets, err := c.Inner.AppsV1().StatefulSets("").List(metaV1.ListOptions{})
	if err != nil {
		return nil, xerrors.Errorf("could not get stateful set: %w", err)
	}
	for _, statefulSet := range statefulSets.Items {
		for _, container := range statefulSet.Spec.Template.Spec.Containers {
			containers = append(containers, domain.KubernetesContainer{Container: container})
		}
	}

	daemonSets, err := c.Inner.AppsV1().DaemonSets("").List(metaV1.ListOptions{})
	if err != nil {
		return nil, xerrors.Errorf("could not get daemon set: %w", err)
	}
	for _, daemonSet := range daemonSets.Items {
		for _, container := range daemonSet.Spec.Template.Spec.Containers {
			containers = append(containers, domain.KubernetesContainer{Container: container})
		}
	}

	return containers, nil
}
