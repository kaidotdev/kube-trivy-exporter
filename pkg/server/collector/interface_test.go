package collector_test

import (
	"kube-trivy-exporter/pkg/server/collector"
	"reflect"
)

type loggerMock struct {
	collector.ILogger
	fakePrintf func(format string, v ...interface{})
}

func (l loggerMock) Printf(format string, v ...interface{}) {
	l.fakePrintf(format, v...)
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
