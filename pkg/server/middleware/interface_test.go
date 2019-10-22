package middleware_test

import "kube-trivy-exporter/pkg/server/middleware"

type loggerMock struct {
	middleware.ILogger
	fakePrintf func(format string, v ...interface{})
}

func (l loggerMock) Printf(format string, v ...interface{}) {
	l.fakePrintf(format, v...)
}
