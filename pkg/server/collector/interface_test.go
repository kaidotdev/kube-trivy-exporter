package collector_test

import (
	"context"
	"kube-trivy-exporter/pkg/server/collector"
	"reflect"

	v1 "k8s.io/api/core/v1"
)

type loggerMock struct {
	collector.ILogger
	fakeErrorf func(format string, v ...interface{})
	fakeInfof  func(format string, v ...interface{})
	fakeDebugf func(format string, v ...interface{})
}

func (l loggerMock) Errorf(format string, v ...interface{}) {
	l.fakeErrorf(format, v...)
}

func (l loggerMock) Infof(format string, v ...interface{}) {
	l.fakeInfof(format, v...)
}

func (l loggerMock) Debugf(format string, v ...interface{}) {
	l.fakeDebugf(format, v...)
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
	fakeDo             func(context.Context, string) ([]byte, error)
	fakeUpdateDatabase func(context.Context) ([]byte, error)
	fakeClearCache     func(context.Context) ([]byte, error)
}

func (t *trivyClientMock) Do(ctx context.Context, image string) ([]byte, error) {
	return t.fakeDo(ctx, image)
}

func (t *trivyClientMock) UpdateDatabase(ctx context.Context) ([]byte, error) {
	return t.fakeUpdateDatabase(ctx)
}

func (t *trivyClientMock) ClearCache(ctx context.Context) ([]byte, error) {
	return t.fakeClearCache(ctx)
}
