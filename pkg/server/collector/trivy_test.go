package collector_test

import (
	"context"
	"errors"
	"fmt"
	"kube-trivy-exporter/pkg/server/collector"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
)

func TestTrivyCollectorDescribe(t *testing.T) {
	tests := []struct {
		name         string
		receiver     *collector.TrivyCollector
		in           chan *prometheus.Desc
		want         *prometheus.Desc
		optsFunction func(interface{}) cmp.Option
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			collector.NewTrivyCollector(
				loggerMock{},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return []v1.Container{}, nil
					},
				},
				&trivyClientMock{
					fakeDo: func(ctx context.Context, image string) ([]byte, error) {
						return []byte{}, nil
					},
				},
				1,
			),
			make(chan *prometheus.Desc, 1),
			prometheus.NewDesc(
				"trivy_vulnerabilities",
				"Vulnerabilities detected by trivy",
				[]string{"image", "vulnerabilityId", "pkgName", "installedVersion", "severity"},
				nil,
			),
			func(got interface{}) cmp.Option {
				switch v := got.(type) {
				case *prometheus.Desc:
					return cmp.AllowUnexported(*v)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		name := tt.name
		receiver := tt.receiver
		in := tt.in
		want := tt.want
		optsFunction := tt.optsFunction
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			receiver.Describe(in)
			got := <-in
			if diff := cmp.Diff(want, got, optsFunction(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestTrivyCollectorCollect(t *testing.T) {
	tests := []struct {
		name         string
		receiver     *collector.TrivyCollector
		in           chan prometheus.Metric
		want         prometheus.Metric
		optsFunction func(interface{}) cmp.Option
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			collector.NewTrivyCollector(
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
					fakeUpdateDatabase: func(ctx context.Context) ([]byte, error) {
						return nil, nil
					},
					fakeDo: func(ctx context.Context, image string) ([]byte, error) {
						return []byte(`[{"Target":"fake","Vulnerabilities":[{"VulnerabilityID":"fake"}]}]`), nil
					},
					fakeClearCache: func(ctx context.Context) ([]byte, error) {
						return nil, nil
					},
				},
				1,
			),
			make(chan prometheus.Metric, 1),
			func() prometheus.Gauge {
				gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
					Namespace: "trivy",
					Name:      "vulnerabilities",
					Help:      "Vulnerabilities detected by trivy",
				}, []string{"image", "vulnerabilityId", "pkgName", "installedVersion", "severity"})
				labels := []string{
					"fake",
					"fake",
					"",
					"",
					"",
				}
				gaugeVec.WithLabelValues(labels...).Set(1)
				gauge, err := gaugeVec.GetMetricWithLabelValues(labels...)
				if err != nil {
					t.Fatal()
				}
				return gauge
			}(),
			func(got interface{}) cmp.Option {
				switch got.(type) {
				case prometheus.Metric:
					deref := func(v interface{}) interface{} {
						return reflect.ValueOf(v).Elem().Interface()
					}
					v := deref(got)
					switch reflect.TypeOf(v).Name() {
					case "gauge":
						var opts cmp.Options
						for _, rv := range getRecursiveStructReflectValue(reflect.ValueOf(v)) {
							switch rv.Type().Name() {
							case "selfCollector":
								opts = append(opts, cmpopts.IgnoreUnexported(rv.Interface()))
							default:
								opts = append(opts, cmp.AllowUnexported(rv.Interface()))
							}
						}
						return opts
					default:
						return nil
					}
				}
				return nil
			},
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			collector.NewTrivyCollector(
				loggerMock{
					fakeErrorf: func(format string, v ...interface{}) {
						want := "Failed to scan: failed to update database: fake\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
				&kubernetesClientMock{},
				&trivyClientMock{
					fakeUpdateDatabase: func(ctx context.Context) ([]byte, error) {
						return nil, errors.New("fake")
					},
				},
				1,
			),
			func() chan prometheus.Metric {
				ch := make(chan prometheus.Metric, 1)
				close(ch)
				return ch
			}(),
			nil,
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
		optsFunction := tt.optsFunction
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			receiver.StartLoop(ctx, 10*time.Millisecond)
			time.Sleep(30 * time.Millisecond)
			receiver.Collect(in)
			got := <-in
			cancel()
			if diff := cmp.Diff(want, got, optsFunction(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestTrivyCollectorScan(t *testing.T) {
	type in struct {
		first context.Context
	}

	tests := []struct {
		name            string
		receiver        *collector.TrivyCollector
		in              in
		wantErrorString string
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			collector.NewTrivyCollector(
				loggerMock{},
				&kubernetesClientMock{},
				&trivyClientMock{
					fakeUpdateDatabase: func(ctx context.Context) ([]byte, error) {
						return nil, errors.New("fake")
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			"failed to update database: fake",
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			collector.NewTrivyCollector(
				loggerMock{},
				&kubernetesClientMock{
					fakeContainers: func() ([]v1.Container, error) {
						return nil, errors.New("fake")
					},
				},
				&trivyClientMock{
					fakeUpdateDatabase: func(ctx context.Context) ([]byte, error) {
						return nil, nil
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			"failed to get containers: fake",
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			collector.NewTrivyCollector(
				loggerMock{
					fakeErrorf: func(format string, v ...interface{}) {
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
					fakeUpdateDatabase: func(ctx context.Context) ([]byte, error) {
						return nil, nil
					},
					fakeDo: func(ctx context.Context, image string) ([]byte, error) {
						return nil, errors.New("fake")
					},
					fakeClearCache: func(ctx context.Context) ([]byte, error) {
						return nil, nil
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			"",
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			collector.NewTrivyCollector(
				loggerMock{
					fakeErrorf: func(format string, v ...interface{}) {
						want := "Failed to parse trivy response at fake: invalid character 'k' in literal false (expecting 'l')\n"
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
					fakeUpdateDatabase: func(ctx context.Context) ([]byte, error) {
						return nil, nil
					},
					fakeDo: func(ctx context.Context, image string) ([]byte, error) {
						return []byte("fake"), nil
					},
					fakeClearCache: func(ctx context.Context) ([]byte, error) {
						return nil, nil
					},
				},
				1,
			),
			in{
				context.Background(),
			},
			"",
		},
	}
	for _, tt := range tests {
		name := tt.name
		receiver := tt.receiver
		in := tt.in
		wantErrorString := tt.wantErrorString
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := receiver.Scan(in.first)
			if err != nil {
				gotErrorString := err.Error()
				if diff := cmp.Diff(wantErrorString, gotErrorString); diff != "" {
					t.Errorf("(-want +got):\n%s", diff)
				}
			}
		})
	}
}
