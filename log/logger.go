package log

import (
	"github.com/adrg/xdg"
	"github.com/sirupsen/logrus"
)

const (
	// default log level
	defaultLogLevel = "info"

	// log file name
	logFileName = "go-quai.log"
	// default log directory
	logDir = "nodelogs"
	// default log file params
	defaultLogMaxSize    = 100  // maximum file size before rotation, in MB
	defaultLogMaxBackups = 3    // maximum number of old log files to keep
	defaultLogMaxAge     = 28   // maximum number of days to retain old log files
	defaultLogCompress   = true // whether to compress the rotated log files using gzip
)

var (
	// logger instance used by the application
	logger Logger

	// TODO: consider refactoring to dinamically read the app name (i.e. "go-quai") ?
	// default logfile path
	defaultLogFilePath = xdg.DataHome + "/" + "go-quai" + "/" + logDir + "/" + logFileName
)

func init() {
	entry := logrus.NewEntry(logrus.StandardLogger())
	logger = &LogWrapper{
		entry: entry,
	}
	ConfigureLogger(
		WithLevel(defaultLogLevel),
		WithOutput(ToLogFile(defaultLogFilePath)),
	)
	logger.Infof("Global Logger started. Writing logs to: %s", defaultLogFilePath)
}

func New(logFilePath string, logLevel string) *LogWrapper {
	newLogger := logrus.New()
	newLogger.SetOutput(ToLogFile(logFilePath))
	entry := logrus.NewEntry(newLogger)
	newWrapper := &LogWrapper{
		entry: entry,
	}
	ConfigureCustomLogger(newWrapper,
		WithLevel(logLevel),
	)
	newWrapper.Info("Shard Logger started", "path", logFilePath, "level", logLevel)
	return newWrapper
}

func ConfigureCustomLogger(logger *LogWrapper, opts ...Options) {
	for _, opt := range opts {
		opt(logger)
	}
}

func ConfigureLogger(opts ...Options) {
	for _, opt := range opts {
		opt(logger.(*LogWrapper))
	}
}

func WithField(key string, val interface{}) Logger {
	return logger.WithField(key, val)
}

func Trace(msg string, args ...interface{}) {
	logger.Trace(ConstructLogMessage(msg, args...))
}

func Tracef(msg string, args ...interface{}) {
	logger.Tracef(msg, args...)
}

func Debug(msg string, args ...interface{}) {
	logger.Debug(ConstructLogMessage(msg, args...))
}

func Debugf(msg string, args ...interface{}) {
	logger.Debugf(msg, args...)
}

func Info(msg string, args ...interface{}) {
	logger.Info(ConstructLogMessage(msg, args...))
}

func Infof(msg string, args ...interface{}) {
	logger.Infof(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	logger.Warn(ConstructLogMessage(msg, args...))
}

func Warnf(msg string, args ...interface{}) {
	logger.Warnf(msg, args...)
}

func Error(msg string, args ...interface{}) {
	logger.Error(ConstructLogMessage(msg, args...))
}

func Errorf(msg string, args ...interface{}) {
	logger.Errorf(msg, args...)
}

func Fatal(msg string, args ...interface{}) {
	logger.Fatal(ConstructLogMessage(msg, args...))
}

func Fatalf(msg string, args ...interface{}) {
	logger.Fatalf(msg, args...)
}
