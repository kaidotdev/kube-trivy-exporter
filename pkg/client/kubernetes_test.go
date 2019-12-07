package client_test

import (
	"errors"
	"fmt"
	"kube-trivy-exporter/pkg/client"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	apiV1 "k8s.io/api/apps/v1"
	coreV1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	appsV1 "k8s.io/client-go/kubernetes/typed/apps/v1"
)

type kubernetesClientsetMock struct {
	kubernetes.Interface
	fakeDeploymentList  func(metaV1.ListOptions) (*apiV1.DeploymentList, error)
	fakeStatefulSetList func(metaV1.ListOptions) (*apiV1.StatefulSetList, error)
	fakeDaemonSetList   func(metaV1.ListOptions) (*apiV1.DaemonSetList, error)
}

func (k *kubernetesClientsetMock) AppsV1() appsV1.AppsV1Interface {
	return &appsV1Mock{
		fakeDeploymentList:  k.fakeDeploymentList,
		fakeStatefulSetList: k.fakeStatefulSetList,
		fakeDaemonSetList:   k.fakeDaemonSetList,
	}
}

type appsV1Mock struct {
	appsV1.AppsV1Interface
	fakeDeploymentList  func(metaV1.ListOptions) (*apiV1.DeploymentList, error)
	fakeStatefulSetList func(metaV1.ListOptions) (*apiV1.StatefulSetList, error)
	fakeDaemonSetList   func(metaV1.ListOptions) (*apiV1.DaemonSetList, error)
}

func (a *appsV1Mock) Deployments(namespace string) appsV1.DeploymentInterface {
	return &deploymentMock{
		fakeList: a.fakeDeploymentList,
	}
}

type deploymentMock struct {
	appsV1.DeploymentInterface
	fakeList func(metaV1.ListOptions) (*apiV1.DeploymentList, error)
}

func (d *deploymentMock) List(opts metaV1.ListOptions) (*apiV1.DeploymentList, error) {
	return d.fakeList(opts)
}

func (a *appsV1Mock) StatefulSets(namespace string) appsV1.StatefulSetInterface {
	return &statefulSetMock{
		fakeList: a.fakeStatefulSetList,
	}
}

type statefulSetMock struct {
	appsV1.StatefulSetInterface
	fakeList func(metaV1.ListOptions) (*apiV1.StatefulSetList, error)
}

func (s *statefulSetMock) List(opts metaV1.ListOptions) (*apiV1.StatefulSetList, error) {
	return s.fakeList(opts)
}

func (a *appsV1Mock) DaemonSets(namespace string) appsV1.DaemonSetInterface {
	return &daemonSetMock{
		fakeList: a.fakeDaemonSetList,
	}
}

type daemonSetMock struct {
	appsV1.DaemonSetInterface
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

	type want struct {
		first []v1.Container
	}

	tests := []struct {
		name            string
		receiver        *client.KubernetesClient
		want            want
		wantErrorString string
		optsFunction    func(interface{}) cmp.Option
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
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
			want{
				[]v1.Container{
					{
						Image: "deployment",
					},
					{
						Image: "statefulSet",
					},
					{
						Image: "daemonSet",
					},
				},
			},
			"",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			&client.KubernetesClient{
				Inner: &kubernetesClientsetMock{
					fakeDeploymentList: func(opts metaV1.ListOptions) (*apiV1.DeploymentList, error) {
						return nil, errors.New("fake")
					},
				},
			},
			want{
				nil,
			},
			"could not get deployment: fake",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
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
			want{
				nil,
			},
			"could not get stateful set: fake",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
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
		name := tt.name
		receiver := tt.receiver
		want := tt.want
		wantErrorString := tt.wantErrorString
		optsFunction := tt.optsFunction
		t.Run(name, func(t *testing.T) {
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
