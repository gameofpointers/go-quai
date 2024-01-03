package log

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

type Logger interface {
	Trace(msg string, args ...interface{})
	Tracef(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Debugf(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
	Fatal(msg string, args ...interface{})
	Fatalf(msg string, args ...interface{})

	WithField(key string, val interface{}) Logger
}

type LogWrapper struct {
	entry *logrus.Entry
}

// Interface assertion
var _ Logger = (*LogWrapper)(nil)

func (l *LogWrapper) Trace(msg string, args ...interface{}) {
	l.entry.Trace(ConstructLogMessage(msg, args...))
}

func (l *LogWrapper) Tracef(msg string, args ...interface{}) {
	l.entry.Tracef(msg, args...)
}

func (l *LogWrapper) Debug(msg string, args ...interface{}) {
	l.entry.Debug(ConstructLogMessage(msg, args...))
}

func (l *LogWrapper) Debugf(msg string, args ...interface{}) {
	l.entry.Debugf(msg, args...)
}

func (l *LogWrapper) Info(msg string, args ...interface{}) {
	l.entry.Info(ConstructLogMessage(msg, args...))
}

func (l *LogWrapper) Infof(msg string, args ...interface{}) {
	l.entry.Infof(msg, args...)
}

func (l *LogWrapper) Warn(msg string, args ...interface{}) {
	l.entry.Warn(ConstructLogMessage(msg, args...))
}

func (l *LogWrapper) Warnf(msg string, args ...interface{}) {
	l.entry.Warnf(msg, args...)
}

func (l *LogWrapper) Error(msg string, args ...interface{}) {
	l.entry.Error(ConstructLogMessage(msg, args...))
}

func (l *LogWrapper) Errorf(msg string, args ...interface{}) {
	l.entry.Errorf(msg, args...)
}

func (l *LogWrapper) Fatal(msg string, args ...interface{}) {
	l.entry.Fatal(ConstructLogMessage(msg, args...))
}

func (l *LogWrapper) Fatalf(msg string, args ...interface{}) {
	l.entry.Fatalf(msg, args...)
}

func (l *LogWrapper) WithField(key string, val interface{}) Logger {
	return &LogWrapper{entry: l.entry.WithField(key, val)}
}

func ConstructLogMessage(msg string, fields ...interface{}) string {
	var pairs []string

	if len(fields) != 1 {
		// Sometimes we want to log a single string,
		if len(fields)%2 != 0 {
			fields = append(fields, "MISSING VALUE")
		}

		for i := 0; i < len(fields); i += 2 {
			key := fields[i]
			value := fields[i+1]
			pairs = append(pairs, fmt.Sprintf("%v=%v", key, value))
		}
	}
	return fmt.Sprintf("%-40s %s", msg, strings.Join(pairs, " "))
}
