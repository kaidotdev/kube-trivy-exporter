package middleware_test

import "kube-trivy-exporter/pkg/server/middleware"

type loggerMock struct {
	middleware.ILogger
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
