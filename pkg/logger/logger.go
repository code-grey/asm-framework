package logger

import (
	"fmt"
	"log/slog"
	"os"
)

// Log is the global logger instance
var Log *slog.Logger

func init() {
	// Provide a default fallback logger before InitLogger is called
	Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
}

// InitLogger initializes the global logger
func InitLogger(debug bool, jsonFormat bool) {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if debug {
		opts.Level = slog.LevelDebug
	}

	if jsonFormat {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	Log = slog.New(handler)
	slog.SetDefault(Log)
}

// Fatal logs an error and exits the program
func Fatal(msg string, args ...any) {
	Log.Error(msg, args...)
	os.Exit(1)
}

// Fatalf logs a formatted error and exits the program
func Fatalf(format string, args ...any) {
	Log.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...any) {
	Log.Error(fmt.Sprintf(format, args...))
}

// Infof logs a formatted info message
func Infof(format string, args ...any) {
	Log.Info(fmt.Sprintf(format, args...))
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...any) {
	Log.Debug(fmt.Sprintf(format, args...))
}

