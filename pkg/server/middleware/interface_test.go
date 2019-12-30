package middleware_test

import "kube-trivy-exporter/pkg/server/middleware"

type loggerMock struct {
	middleware.ILogger
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
