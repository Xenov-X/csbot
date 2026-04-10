package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the bot configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Logging  LoggingConfig  `yaml:"logging"`
	Timeouts TimeoutConfig  `yaml:"timeouts"`
}

// ServerConfig represents server connection settings
type ServerConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Insecure bool   `yaml:"insecure"`
	Proxy    string `yaml:"proxy"` // HTTP/HTTPS proxy URL (e.g., http://127.0.0.1:8080)
}

// LoggingConfig represents logging settings
type LoggingConfig struct {
	Level      string `yaml:"level"`       // debug, info, warn, error
	File       string `yaml:"file"`        // log file path
	JSONFormat bool   `yaml:"json_format"` // use JSON format
}

// TimeoutConfig represents timeout settings
type TimeoutConfig struct {
	HTTPTimeout int `yaml:"http_timeout"` // seconds
	TaskTimeout int `yaml:"task_timeout"` // seconds
}

// LoadConfig loads configuration from file with environment variable overrides
func LoadConfig(filename string) (*Config, error) {
	// Set defaults
	cfg := &Config{
		Server: ServerConfig{
			Port:     50443,
			Insecure: false,
		},
		Logging: LoggingConfig{
			Level:      "info",
			JSONFormat: false,
		},
		Timeouts: TimeoutConfig{
			HTTPTimeout: 30,
			TaskTimeout: 300,
		},
	}

	// Load from file if exists
	if filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
			// File doesn't exist, use defaults + env vars
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables
	if host := os.Getenv("CS_HOST"); host != "" {
		cfg.Server.Host = host
	}
	if port := os.Getenv("CS_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &cfg.Server.Port)
	}
	if username := os.Getenv("CS_USERNAME"); username != "" {
		cfg.Server.Username = username
	}
	if password := os.Getenv("CS_PASSWORD"); password != "" {
		cfg.Server.Password = password
	}
	if insecure := os.Getenv("CS_INSECURE"); insecure != "" {
		cfg.Server.Insecure = strings.ToLower(insecure) == "true"
	}
	// Support both CS_PROXY and standard HTTP_PROXY/HTTPS_PROXY
	if proxy := os.Getenv("CS_PROXY"); proxy != "" {
		cfg.Server.Proxy = proxy
	} else if proxy := os.Getenv("HTTPS_PROXY"); proxy != "" {
		cfg.Server.Proxy = proxy
	} else if proxy := os.Getenv("HTTP_PROXY"); proxy != "" {
		cfg.Server.Proxy = proxy
	}
	if level := os.Getenv("CS_LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}
	if logfile := os.Getenv("CS_LOG_FILE"); logfile != "" {
		cfg.Logging.File = logfile
	}

	return cfg, nil
}

// Validate checks if required configuration is present
func (c *Config) Validate() error {
	if c.Server.Host == "" {
		return fmt.Errorf("server host is required")
	}
	if c.Server.Username == "" {
		return fmt.Errorf("server username is required")
	}
	if c.Server.Password == "" {
		return fmt.Errorf("server password is required")
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Server.Port)
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s (must be debug, info, warn, or error)", c.Logging.Level)
	}

	return nil
}
