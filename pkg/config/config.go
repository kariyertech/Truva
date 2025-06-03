package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Logging    LoggingConfig    `yaml:"logging"`
	Kubernetes KubernetesConfig `yaml:"kubernetes"`
	UI         UIConfig         `yaml:"ui"`
	Sync       SyncConfig       `yaml:"sync"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Host string `yaml:"host"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	File   string `yaml:"file"`
	Format string `yaml:"format"`
}

type KubernetesConfig struct {
	ConfigPath string `yaml:"config_path"`
}

type UIConfig struct {
	TemplatePath string `yaml:"template_path"`
}

type SyncConfig struct {
	DebounceDuration string `yaml:"debounce_duration"`
	BatchSize        int    `yaml:"batch_size"`
}

type MonitoringConfig struct {
	MetricsEnabled     bool `yaml:"metrics_enabled"`
	HealthCheckEnabled bool `yaml:"health_check_enabled"`
}

var GlobalConfig *Config

func LoadConfig(configPath string) error {
	if configPath == "" {
		configPath = "config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	GlobalConfig = &config
	return nil
}

func GetConfig() *Config {
	if GlobalConfig == nil {
		// Default config if not loaded
		templatePath := getDefaultTemplatePath()
		GlobalConfig = &Config{
			Server: ServerConfig{
				Port: 8080,
				Host: "localhost",
			},
			Logging: LoggingConfig{
				Level:  "info",
				File:   "app.log",
				Format: "text",
			},
			UI: UIConfig{
				TemplatePath: templatePath,
			},
			Sync: SyncConfig{
				DebounceDuration: "2s",
				BatchSize:        10,
			},
		}
	}
	return GlobalConfig
}

// getDefaultTemplatePath returns the template path relative to executable
func getDefaultTemplatePath() string {
	execPath, err := os.Executable()
	if err != nil {
		// Fallback to current working directory
		return "templates/index.html"
	}

	execDir := filepath.Dir(execPath)
	templatePath := filepath.Join(execDir, "templates", "index.html")

	// Check if template exists at executable location
	if _, err := os.Stat(templatePath); err == nil {
		return templatePath
	}

	// Fallback: check current working directory
	wd, err := os.Getwd()
	if err == nil {
		templatePath = filepath.Join(wd, "templates", "index.html")
		if _, err := os.Stat(templatePath); err == nil {
			return templatePath
		}
	}

	// Final fallback
	return "templates/index.html"
}

func (c *Config) GetDebounceDuration() time.Duration {
	duration, err := time.ParseDuration(c.Sync.DebounceDuration)
	if err != nil {
		return 2 * time.Second // default
	}
	return duration
}
