package collector_test

import (
	"context"
	"errors"
	"fmt"
	"kube-trivy-exporter/pkg/domain"
	"kube-trivy-exporter/pkg/server/collector"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/prometheus/client_golang/prometheus"
)

type trivyResponseAdapterMock struct {
	collector.ITrivyResponseAdapter
	fakeRequest func(context.Context) ([]domain.TrivyResponse, error)
}

func (a *trivyResponseAdapterMock) Request(ctx context.Context) ([]domain.TrivyResponse, error) {
	return a.fakeRequest(ctx)
}

func TestTrivyCollectorDescribe(t *testing.T) {
	tests := []struct {
		receiver     *collector.TrivyCollector
		in           chan *prometheus.Desc
		want         *prometheus.Desc
		optsFunction func(interface{}) cmp.Option
	}{
		{
			collector.NewTrivyCollector(
				context.Background(),
				loggerMock{},
				&trivyResponseAdapterMock{
					fakeRequest: func(ctx context.Context) ([]domain.TrivyResponse, error) {
						return []domain.TrivyResponse{
							{
								Target: "k8s.gcr.io/kube-addon-manager:v9.0.2 (debian 9.8)",
								Vulnerabilities: []domain.TrivyVulnerability{
									{
										VulnerabilityID:  "CVE-2011-3374",
										PkgName:          "apt",
										InstalledVersion: "1.4.9",
										FixedVersion:     "",
										Title:            "",
										Description:      "",
										Severity:         "LOW",
										References:       nil,
									},
								},
							},
						}, nil
					},
				},
				10*time.Millisecond,
			),
			make(chan *prometheus.Desc, 1),
			prometheus.NewDesc(
				"trivy_vulnerabilities",
				"Vulnerabilities detected by trivy",
				[]string{"target", "vulnerabilityId", "pkgName", "installedVersion", "severity"},
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
		receiver := tt.receiver
		in := tt.in
		want := tt.want
		optsFunction := tt.optsFunction
		t.Run(fmt.Sprintf("%#v/%#v", receiver, in), func(t *testing.T) {
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
		receiver     *collector.TrivyCollector
		in           chan prometheus.Metric
		want         prometheus.Metric
		optsFunction func(interface{}) cmp.Option
	}{
		{
			collector.NewTrivyCollector(
				context.Background(),
				loggerMock{},
				&trivyResponseAdapterMock{
					fakeRequest: func(ctx context.Context) ([]domain.TrivyResponse, error) {
						return []domain.TrivyResponse{
							{
								Target: "k8s.gcr.io/kube-addon-manager:v9.0.2 (debian 9.8)",
								Vulnerabilities: []domain.TrivyVulnerability{
									{
										VulnerabilityID:  "CVE-2011-3374",
										PkgName:          "apt",
										InstalledVersion: "1.4.9",
										FixedVersion:     "",
										Title:            "",
										Description:      "",
										Severity:         "LOW",
										References:       nil,
									},
								},
							},
						}, nil
					},
				},
				10*time.Millisecond,
			),
			make(chan prometheus.Metric, 1),
			func() prometheus.Gauge {
				gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
					Namespace: "trivy",
					Name:      "vulnerabilities",
					Help:      "Vulnerabilities detected by trivy",
				}, []string{"target", "vulnerabilityId", "pkgName", "installedVersion", "severity"})
				labels := []string{
					"k8s.gcr.io/kube-addon-manager:v9.0.2 (debian 9.8)",
					"CVE-2011-3374",
					"apt",
					"1.4.9",
					"LOW",
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
			collector.NewTrivyCollector(
				context.Background(),
				loggerMock{
					fakePrintf: func(format string, v ...interface{}) {
						want := "Failed to collect metrics: fake\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
				&trivyResponseAdapterMock{
					fakeRequest: func(ctx context.Context) ([]domain.TrivyResponse, error) {
						return nil, errors.New("fake")
					},
				},
				10*time.Millisecond,
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
		{
			collector.NewTrivyCollector(
				context.Background(),
				loggerMock{
					fakePrintf: func(format string, v ...interface{}) {
						want := "panic: fake\n"
						got := fmt.Sprintf(format, v...)
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("(-want +got):\n%s", diff)
						}
					},
				},
				&trivyResponseAdapterMock{
					fakeRequest: func(ctx context.Context) ([]domain.TrivyResponse, error) {
						panic(errors.New("fake"))
					},
				},
				10*time.Millisecond,
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
		{
			collector.NewTrivyCollector(
				func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return ctx
				}(),
				loggerMock{},
				&trivyResponseAdapterMock{},
				10*time.Millisecond,
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
		receiver := tt.receiver
		in := tt.in
		want := tt.want
		optsFunction := tt.optsFunction
		t.Run(fmt.Sprintf("%#v/%#v", receiver, in), func(t *testing.T) {
			t.Parallel()

			time.Sleep(20 * time.Millisecond)
			receiver.Collect(in)
			got := <-in
			receiver.Cancel()
			if diff := cmp.Diff(want, got, optsFunction(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}
