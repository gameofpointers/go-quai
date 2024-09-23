package log

import (
	"io"
	"os"
	"path/filepath"

	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
)

type Fields = logrus.Fields
type Logger = logrus.Logger

const (
	// default log level
	defaultLogLevel = logrus.InfoLevel
	defaultLogSize  = 500 // megabytes

	// log file name
	globalLogFileName = "global.log"
	// default log directory
	logDir = "nodelogs"
	// default log file params
	defaultLogMaxSize    = 100  // maximum file size before rotation, in MB
	defaultLogMaxBackups = 10   // maximum number of old log files to keep
	defaultLogMaxAge     = 28   // maximum number of days to retain old log files
	defaultLogCompress   = true // whether to compress the rotated log files using gzip
)

var (
	// logger instance used by the application
	Global *logrus.Logger

	// TODO: consider refactoring to dinamically read the app name (i.e. "go-quai") ?
	// default logfile path
	defaultLogFilePath = "./" + logDir + "/" + globalLogFileName
)

func init() {
	Global = createStandardLogger(defaultLogFilePath, defaultLogLevel.String(), 500, true)
}

func SetGlobalLogger(logFilename string, logLevel string) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = defaultLogLevel
	}
	Global.SetLevel(level)

	if logFilename == "" {
		Global.WithFields(Fields{
			"path":  defaultLogFilePath,
			"level": level.String(),
		}).Info("Global logger started")
		return
	}

	output := &lumberjack.Logger{
		Filename:   logFilename,
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28, //days
	}
	Global.SetOutput(io.MultiWriter(output, os.Stdout))

	Global.WithFields(Fields{
		"path":  logFilename,
		"level": level.String(),
	}).Info("Global logger started")
}

func NewLogger(logFilename string, logLevel string, logSize int) *logrus.Logger {
	if logFilename == "" {
		logFilename = defaultLogFilePath
	}
	shardLogger := createStandardLogger(filepath.Join(logDir, logFilename), logLevel, logSize, false)
	shardLogger.WithFields(Fields{
		"path":  logFilename,
		"level": logLevel,
	}).Info("Shard logger started")
	return shardLogger
}

func createStandardLogger(logFilename string, logLevel string, logSize int, stdOut bool) *logrus.Logger {
	logger := logrus.New()
	output := &lumberjack.Logger{
		Filename:   logFilename,
		MaxSize:    logSize, // megabytes
		MaxBackups: 3,
		MaxAge:     28, //days
	}

	if stdOut {
		logger.SetOutput(io.MultiWriter(output, os.Stdout))
	} else {
		logger.SetOutput(output)
	}

	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		PadLevelText:    true,
		FullTimestamp:   true,
		TimestampFormat: "01-02|15:04:05.000",
	})
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = defaultLogLevel
	}
	logger.SetLevel(level)
	return logger
}
