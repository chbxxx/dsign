package logger

import "fmt"

// Logger for common
type Logger interface {
	// Log a message at the given level with context key/value pairs
	Trace(msg string, ctx ...interface{})
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
	Crit(msg string, ctx ...interface{})
}

var DefaultLogger = defaultLogger{}

type defaultLogger struct{}

var _ Logger = defaultLogger{}

func (defaultLogger) Trace(msg string, ctx ...interface{}) {
	fmt.Println(msg, ctx)
}

func (defaultLogger) Debug(msg string, ctx ...interface{}) {
	fmt.Println(msg, ctx)
}

func (defaultLogger) Info(msg string, ctx ...interface{}) {
	fmt.Println(msg, ctx)
}

func (defaultLogger) Warn(msg string, ctx ...interface{}) {
	fmt.Println(msg, ctx)
}

func (defaultLogger) Error(msg string, ctx ...interface{}) {
	fmt.Println(msg, ctx)
}

func (defaultLogger) Crit(msg string, ctx ...interface{}) {
	fmt.Println(msg, ctx)
}
