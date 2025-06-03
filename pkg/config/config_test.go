package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file for testing
	tempDir, err := os.MkdirTemp("", "truva-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `server:
  host: "0.0.0.0"
  port: 9090

logging:
  level: "debug"
  file: "custom.log"

kubernetes:
  config_path: "/custom/path/kubeconfig"

ui:
  template_path: "custom/templates/index.html"

sync:
  debounce_duration: "2s"
  batch_size: 5

monitoring:
  metrics_enabled: false
  health_check_enabled: true
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	tests := []struct {
		name          string
		configPath    string
		wantErr       bool
		expectedHost  string
		expectedPort  int
		expectedLevel string
	}{
		{
			name:          "valid config file",
			configPath:    configFile,
			wantErr:       false,
			expectedHost:  "0.0.0.0",
			expectedPort:  9090,
			expectedLevel: "debug",
		},
		{
			name:       "non-existing config file",
			configPath: "/non/existing/config.yaml",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global config before each test
			GlobalConfig = nil

			err := LoadConfig(tt.configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				cfg := GetConfig()
				if cfg.Server.Host != tt.expectedHost {
					t.Errorf("LoadConfig() host = %v, want %v", cfg.Server.Host, tt.expectedHost)
				}
				if cfg.Server.Port != tt.expectedPort {
					t.Errorf("LoadConfig() port = %v, want %v", cfg.Server.Port, tt.expectedPort)
				}
				if cfg.Logging.Level != tt.expectedLevel {
					t.Errorf("LoadConfig() logging level = %v, want %v", cfg.Logging.Level, tt.expectedLevel)
				}
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	// Test when config is not loaded - should return default config
	GlobalConfig = nil
	cfg := GetConfig()
	if cfg == nil {
		t.Errorf("GetConfig() should return default config when not loaded")
	}
	if cfg.Server.Host != "localhost" {
		t.Errorf("GetConfig() default host = %v, want %v", cfg.Server.Host, "localhost")
	}

	// Test when config is loaded
	testConfig := &Config{
		Server: ServerConfig{
			Host: "test-host",
			Port: 8080,
		},
	}
	GlobalConfig = testConfig
	cfg = GetConfig()
	if cfg == nil {
		t.Errorf("GetConfig() should return config when loaded")
	}
	if cfg.Server.Host != "test-host" {
		t.Errorf("GetConfig() host = %v, want %v", cfg.Server.Host, "test-host")
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test default config when no config is loaded
	GlobalConfig = nil
	cfg := GetConfig()

	// Test default values
	if cfg.Server.Host != "localhost" {
		t.Errorf("Default server host = %v, want %v", cfg.Server.Host, "localhost")
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Default server port = %v, want %v", cfg.Server.Port, 8080)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Default logging level = %v, want %v", cfg.Logging.Level, "info")
	}
	if cfg.Logging.File != "app.log" {
		t.Errorf("Default logging file = %v, want %v", cfg.Logging.File, "app.log")
	}
	if cfg.UI.TemplatePath != "templates/index.html" {
		t.Errorf("Default UI template path = %v, want %v", cfg.UI.TemplatePath, "templates/index.html")
	}
	if cfg.Sync.DebounceDuration != "2s" {
		t.Errorf("Default sync debounce duration = %v, want %v", cfg.Sync.DebounceDuration, "2s")
	}
	if cfg.Sync.BatchSize != 10 {
		t.Errorf("Default sync batch size = %v, want %v", cfg.Sync.BatchSize, 10)
	}
}

func TestInvalidYAML(t *testing.T) {
	// Create a config file with invalid YAML
	tempDir, err := os.MkdirTemp("", "truva-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Invalid YAML content
	configContent := `server:
  host: "localhost
  port: 8080
  invalid_yaml: [
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	err = LoadConfig(configFile)
	if err == nil {
		t.Errorf("LoadConfig() should fail with invalid YAML")
	}
}
