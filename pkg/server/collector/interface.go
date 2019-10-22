package collector

type ILogger interface {
	Printf(format string, v ...interface{})
	Fatalf(format string, v ...interface{})
}
