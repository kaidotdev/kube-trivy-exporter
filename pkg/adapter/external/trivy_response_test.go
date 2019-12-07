package external_test

import (
	"context"
	"errors"
	"fmt"
	"kube-trivy-exporter/pkg/adapter/external"
	"kube-trivy-exporter/pkg/domain"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
)

func TestTrivyResponseRequest(t *testing.T) {
	type in struct {
		first context.Context
	}

	type want struct {
		first []domain.TrivyResponse
	}

	tests := []struct {
		name            string
		receiver        *external.TrivyResponseAdapter
		in              in
		want            want
		wantErrorString string
		optsFunction    func(interface{}) cmp.Option
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			external.NewTrivyResponseAdapter(
				loggerMock{},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return []v1.Container{
							{
								Image: "fake",
							},
						}, nil
					},
				},
				&trivyClientMock{
					fakeDo: func(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
						return []domain.TrivyResponse{
							{
								Target: "fake",
							},
						}, nil
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			want{
				[]domain.TrivyResponse{
					{
						Target: "fake",
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
			external.NewTrivyResponseAdapter(
				loggerMock{},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return []v1.Container{
							{
								Image: "fake",
							},
							{
								Image: "fake",
							},
						}, nil
					},
				},
				&trivyClientMock{
					fakeDo: func(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
						return []domain.TrivyResponse{
							{
								Target: "fake",
							},
						}, nil
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			want{
				[]domain.TrivyResponse{
					{
						Target: "fake",
					},
					{
						Target: "fake",
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
			external.NewTrivyResponseAdapter(
				loggerMock{},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return []v1.Container{
							{
								Image: "fake",
							},
							{
								Image: "fake",
							},
						}, nil
					},
				},
				&trivyClientMock{
					fakeDo: func(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
						return []domain.TrivyResponse{
							{
								Target: "fake",
							},
						}, nil
					},
				},
				2,
			),
			in{
				context.Background(),
			},
			want{
				[]domain.TrivyResponse{
					{
						Target: "fake",
					},
					{
						Target: "fake",
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
			external.NewTrivyResponseAdapter(
				loggerMock{},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return nil, errors.New("fake")
					},
				},
				&trivyClientMock{},
				1,
			),
			in{
				context.Background(),
			},
			want{
				nil,
			},
			"could not get containers: fake",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			external.NewTrivyResponseAdapter(
				loggerMock{
					fakePrintf: func(format string, v ...interface{}) {
						want := "Failed to detect vulnerability at fake: fake\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return []v1.Container{
							{
								Image: "fake",
							},
						}, nil
					},
				},
				&trivyClientMock{
					fakeDo: func(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
						return nil, errors.New("fake")
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			want{
				nil,
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
			external.NewTrivyResponseAdapter(
				loggerMock{
					fakePrintf: func(format string, v ...interface{}) {
						want := "Failed to detect vulnerability at fake: done\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return []v1.Container{
							{
								Image: "fake",
							},
						}, nil
					},
				},
				&trivyClientMock{
					fakeDo: func(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
						<-ctx.Done()
						return nil, errors.New("done")
					},
				},
				1,
			),
			in{
				func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return ctx
				}(),
			},
			want{
				nil,
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
			external.NewTrivyResponseAdapter(
				loggerMock{
					fakePrintf: func(format string, v ...interface{}) {
						want := "panic: fake\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return []v1.Container{
							{
								Image: "fake",
							},
						}, nil
					},
				},
				&trivyClientMock{
					fakeDo: func(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
						panic(errors.New("fake"))
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			want{
				nil,
			},
			"",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
	}
	for _, tt := range tests {
		name := tt.name
		receiver := tt.receiver
		in := tt.in
		want := tt.want
		wantErrorString := tt.wantErrorString
		optsFunction := tt.optsFunction
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := receiver.Request(in.first)
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
