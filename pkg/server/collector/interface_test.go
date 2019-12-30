package collector_test

import (
	"context"
	"kube-trivy-exporter/pkg/server/collector"
	"reflect"

	v1 "k8s.io/api/core/v1"
)

type loggerMock struct {
	collector.ILogger
	fakeError func(format string, v ...interface{})
	fakeInfo  func(format string, v ...interface{})
	fakeDebug func(format string, v ...interface{})
}

func (l loggerMock) Error(format string, v ...interface{}) {
	l.fakeError(format, v...)
}

func (l loggerMock) Info(format string, v ...interface{}) {
	l.fakeInfo(format, v...)
}

func (l loggerMock) Debug(format string, v ...interface{}) {
	l.fakeDebug(format, v...)
}

func getRecursiveStructReflectValue(rv reflect.Value) []reflect.Value {
	var values []reflect.Value
	switch rv.Kind() {
	case reflect.Ptr:
		values = append(values, getRecursiveStructReflectValue(rv.Elem())...)
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			values = append(values, getRecursiveStructReflectValue(rv.Index(i))...)
		}
	case reflect.Map:
		for _, k := range rv.MapKeys() {
			values = append(values, getRecursiveStructReflectValue(rv.MapIndex(k))...)
		}
	case reflect.Struct:
		values = append(values, reflect.New(rv.Type()).Elem())
		for i := 0; i < rv.NumField(); i++ {
			values = append(values, getRecursiveStructReflectValue(rv.Field(i))...)
		}
	default:
	}
	return values
}

type kubernetesClientMock struct {
	collector.IKubernetesClient
	fakeContainers func() ([]v1.Container, error)
}

func (k *kubernetesClientMock) Containers() ([]v1.Container, error) {
	return k.fakeContainers()
}

type trivyClientMock struct {
	collector.ITrivyClient
	fakeDo func(context.Context, string) ([]byte, error)
}

func (t *trivyClientMock) Do(ctx context.Context, image string) ([]byte, error) {
	return t.fakeDo(ctx, image)
}
