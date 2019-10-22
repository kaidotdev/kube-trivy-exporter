package client_test

import (
	"errors"
	"fmt"
	"kube-trivy-exporter/pkg/client"
	"kube-trivy-exporter/pkg/domain"
	"testing"

	"github.com/google/go-cmp/cmp"
	apiV1 "k8s.io/api/apps/v1"
	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/apps/v1"
)

type kubernetesClientsetMock struct {
	kubernetes.Interface
	fakeDeploymentList  func(metaV1.ListOptions) (*apiV1.DeploymentList, error)
	fakeStatefulSetList func(metaV1.ListOptions) (*apiV1.StatefulSetList, error)
	fakeDaemonSetList   func(metaV1.ListOptions) (*apiV1.DaemonSetList, error)
}

func (k *kubernetesClientsetMock) AppsV1() v1.AppsV1Interface {
	return &appsV1Mock{
		fakeDeploymentList:  k.fakeDeploymentList,
		fakeStatefulSetList: k.fakeStatefulSetList,
		fakeDaemonSetList:   k.fakeDaemonSetList,
	}
}

type appsV1Mock struct {
	v1.AppsV1Interface
	fakeDeploymentList  func(metaV1.ListOptions) (*apiV1.DeploymentList, error)
	fakeStatefulSetList func(metaV1.ListOptions) (*apiV1.StatefulSetList, error)
	fakeDaemonSetList   func(metaV1.ListOptions) (*apiV1.DaemonSetList, error)
}

func (a *appsV1Mock) Deployments(namespace string) v1.DeploymentInterface {
	return &deploymentMock{
		fakeList: a.fakeDeploymentList,
	}
}

type deploymentMock struct {
	v1.DeploymentInterface
	fakeList func(metaV1.ListOptions) (*apiV1.DeploymentList, error)
}

func (d *deploymentMock) List(opts metaV1.ListOptions) (*apiV1.DeploymentList, error) {
	return d.fakeList(opts)
}

func (a *appsV1Mock) StatefulSets(namespace string) v1.StatefulSetInterface {
	return &statefulSetMock{
		fakeList: a.fakeStatefulSetList,
	}
}

type statefulSetMock struct {
	v1.StatefulSetInterface
	fakeList func(metaV1.ListOptions) (*apiV1.StatefulSetList, error)
}

func (s *statefulSetMock) List(opts metaV1.ListOptions) (*apiV1.StatefulSetList, error) {
	return s.fakeList(opts)
}

func (a *appsV1Mock) DaemonSets(namespace string) v1.DaemonSetInterface {
	return &daemonSetMock{
		fakeList: a.fakeDaemonSetList,
	}
}

type daemonSetMock struct {
	v1.DaemonSetInterface
	fakeList func(metaV1.ListOptions) (*apiV1.DaemonSetList, error)
}

func (d *daemonSetMock) List(opts metaV1.ListOptions) (*apiV1.DaemonSetList, error) {
	return d.fakeList(opts)
}

func TestKubernetesClientContainers(t *testing.T) {
	fakeDeployment := apiV1.Deployment{
		Spec: apiV1.DeploymentSpec{
			Template: coreV1.PodTemplateSpec{
				Spec: coreV1.PodSpec{
					Containers: []coreV1.Container{
						{
							Image: "deployment",
						},
					},
				},
			},
		},
	}
	fakeStatefulSet := apiV1.StatefulSet{
		Spec: apiV1.StatefulSetSpec{
			Template: coreV1.PodTemplateSpec{
				Spec: coreV1.PodSpec{
					Containers: []coreV1.Container{
						{
							Image: "statefulSet",
						},
					},
				},
			},
		},
	}
	fakeDaemonSet := apiV1.DaemonSet{
		Spec: apiV1.DaemonSetSpec{
			Template: coreV1.PodTemplateSpec{
				Spec: coreV1.PodSpec{
					Containers: []coreV1.Container{
						{
							Image: "daemonSet",
						},
					},
				},
			},
		},
	}

	type in struct{}

	type want struct {
		first []domain.KubernetesContainer
	}

	tests := []struct {
		receiver        *client.KubernetesClient
		in              in
		want            want
		wantErrorString string
		optsFunction    func(interface{}) cmp.Option
	}{
		{
			&client.KubernetesClient{
				Inner: &kubernetesClientsetMock{
					fakeDeploymentList: func(opts metaV1.ListOptions) (*apiV1.DeploymentList, error) {
						return &apiV1.DeploymentList{
							Items: []apiV1.Deployment{
								fakeDeployment,
							},
						}, nil
					},
					fakeStatefulSetList: func(opts metaV1.ListOptions) (*apiV1.StatefulSetList, error) {
						return &apiV1.StatefulSetList{
							Items: []apiV1.StatefulSet{
								fakeStatefulSet,
							},
						}, nil
					},
					fakeDaemonSetList: func(opts metaV1.ListOptions) (*apiV1.DaemonSetList, error) {
						return &apiV1.DaemonSetList{
							Items: []apiV1.DaemonSet{
								fakeDaemonSet,
							},
						}, nil
					},
				},
			},
			in{},
			want{
				[]domain.KubernetesContainer{
					{
						Container: coreV1.Container{
							Image: "deployment",
						},
					},
					{
						Container: coreV1.Container{
							Image: "statefulSet",
						},
					},
					{
						Container: coreV1.Container{
							Image: "daemonSet",
						},
					},
				},
			},
			"",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			&client.KubernetesClient{
				Inner: &kubernetesClientsetMock{
					fakeDeploymentList: func(opts metaV1.ListOptions) (*apiV1.DeploymentList, error) {
						return nil, errors.New("fake")
					},
				},
			},
			in{},
			want{
				nil,
			},
			"could not get deployment: fake",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			&client.KubernetesClient{
				Inner: &kubernetesClientsetMock{
					fakeDeploymentList: func(opts metaV1.ListOptions) (*apiV1.DeploymentList, error) {
						return &apiV1.DeploymentList{
							Items: []apiV1.Deployment{
								fakeDeployment,
							},
						}, nil
					},
					fakeStatefulSetList: func(opts metaV1.ListOptions) (*apiV1.StatefulSetList, error) {
						return nil, errors.New("fake")
					},
				},
			},
			in{},
			want{
				nil,
			},
			"could not get stateful set: fake",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			&client.KubernetesClient{
				Inner: &kubernetesClientsetMock{
					fakeDeploymentList: func(opts metaV1.ListOptions) (*apiV1.DeploymentList, error) {
						return &apiV1.DeploymentList{
							Items: []apiV1.Deployment{
								fakeDeployment,
							},
						}, nil
					},
					fakeStatefulSetList: func(opts metaV1.ListOptions) (*apiV1.StatefulSetList, error) {
						return &apiV1.StatefulSetList{
							Items: []apiV1.StatefulSet{
								fakeStatefulSet,
							},
						}, nil
					},
					fakeDaemonSetList: func(opts metaV1.ListOptions) (*apiV1.DaemonSetList, error) {
						return nil, errors.New("fake")
					},
				},
			},
			in{},
			want{
				nil,
			},
			"could not get daemon set: fake",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
	}
	for _, tt := range tests {
		receiver := tt.receiver
		in := tt.in
		want := tt.want
		wantErrorString := tt.wantErrorString
		optsFunction := tt.optsFunction
		t.Run(fmt.Sprintf("%#v/%#v", receiver, in), func(t *testing.T) {
			t.Parallel()

			got, err := receiver.Containers()
			if diff := cmp.Diff(want.first, got, optsFunction(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
			if err != nil {
				gotErrorString := err.Error()
				if diff := cmp.Diff(wantErrorString, gotErrorString); diff != "" {
					t.Errorf("(-want +got):\n%s", diff)
				}
			}
		})
	}
}
