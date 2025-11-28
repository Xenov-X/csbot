package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

var levelNames = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

var levelColors = map[LogLevel]string{
	DEBUG: "\033[36m", // Cyan
	INFO:  "\033[32m", // Green
	WARN:  "\033[33m", // Yellow
	ERROR: "\033[31m", // Red
}

const colorReset = "\033[0m"

// Logger is a custom logger with levels
type Logger struct{
	level      LogLevel
	jsonFormat bool
	output     io.Writer
	logger     *log.Logger
	useColor   bool
}

// New creates a new logger
func New(level string, jsonFormat bool, file string) (*Logger, error) {
	var output io.Writer = os.Stdout

	// Open log file if specified
	if file != "" {
		f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		output = io.MultiWriter(os.Stdout, f)
	}

	logLevel := parseLevel(level)
	useColor := file == "" && !jsonFormat // Only use color for stdout non-JSON logs

	return &Logger{
		level:      logLevel,
		jsonFormat: jsonFormat,
		output:     output,
		logger:     log.New(output, "", 0),
		useColor:   useColor,
	}, nil
}

func parseLevel(level string) LogLevel {
	switch level {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

// log writes a log message at the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	message := fmt.Sprintf(format, args...)

	if l.jsonFormat {
		l.logJSON(level, message)
	} else {
		l.logText(level, message)
	}
}

func (l *Logger) logText(level LogLevel, message string) {
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	levelStr := levelNames[level]

	if l.useColor {
		color := levelColors[level]
		l.logger.Printf("%s [%s%s%s] %s", timestamp, color, levelStr, colorReset, message)
	} else {
		l.logger.Printf("%s [%s] %s", timestamp, levelStr, message)
	}
}

func (l *Logger) logJSON(level LogLevel, message string) {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     levelNames[level],
		"message":   message,
	}

	data, _ := json.Marshal(entry)
	l.logger.Println(string(data))
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs an error message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
	os.Exit(1)
}
