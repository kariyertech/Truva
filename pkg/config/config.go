package config

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Environment represents the application environment
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
	Testing     Environment = "testing"
)

// ConfigManager handles environment-specific configuration loading and hot reload
type ConfigManager struct {
	mu              sync.RWMutex
	config          *Config
	environment     Environment
	configPaths     []string
	watcher         *fsnotify.Watcher
	validators      []ConfigValidator
	changeCallbacks []func(*Config)
	ctx             context.Context
	cancel          context.CancelFunc
}

// ConfigValidator defines a function that validates configuration
type ConfigValidator func(*Config) error

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	messages := make([]string, len(e))
	for i, err := range e {
		messages[i] = err.Error()
	}
	return fmt.Sprintf("multiple validation errors: %s", strings.Join(messages, "; "))
}

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Logging        LoggingConfig        `yaml:"logging"`
	LogAggregation LogAggregationConfig `yaml:"log_aggregation"`
	Kubernetes     KubernetesConfig     `yaml:"kubernetes"`
	UI             UIConfig             `yaml:"ui"`
	Auth           AuthConfig           `yaml:"auth"`
	Sync           SyncConfig           `yaml:"sync"`
	Monitoring     MonitoringConfig     `yaml:"monitoring"`
	Credentials    CredentialsConfig    `yaml:"credentials"`
	Secrets        SecretsConfig        `yaml:"secrets"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	Environment    Environment          `yaml:"environment"`
}

type ServerConfig struct {
	Port int       `yaml:"port"`
	Host string    `yaml:"host"`
	TLS  TLSConfig `yaml:"tls"`
}

// TLSConfig holds TLS/HTTPS configuration
type TLSConfig struct {
	Enabled       bool   `yaml:"enabled"`
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`
	AutoTLS       bool   `yaml:"auto_tls"`
	HTTPSPort     int    `yaml:"https_port"`
	RedirectHTTP  bool   `yaml:"redirect_http"`
	MinTLSVersion string `yaml:"min_tls_version"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	File   string `yaml:"file"`
	Format string `yaml:"format"`
}

// LogAggregationConfig holds log aggregation configuration
type LogAggregationConfig struct {
	Enabled bool         `yaml:"enabled"`
	Signoz  SignozConfig `yaml:"signoz"`
}

// SignozConfig holds Signoz-specific configuration
type SignozConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Endpoint      string        `yaml:"endpoint"`
	APIKey        string        `yaml:"api_key"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	Timeout       time.Duration `yaml:"timeout"`
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

type AuthConfig struct {
	Enabled        bool          `yaml:"enabled"`
	RequireAuth    bool          `yaml:"require_auth"`
	JWTSecret      string        `yaml:"jwt_secret"`
	TokenExpiry    time.Duration `yaml:"token_expiry"`
	APIKeys        []string      `yaml:"api_keys"`
	AllowedOrigins []string      `yaml:"allowed_origins"`
	CORS           CORSConfig    `yaml:"cors"`
}

// CredentialsConfig holds configuration for secure credential management
type CredentialsConfig struct {
	Enabled         bool   `yaml:"enabled" env:"TRUVA_CREDENTIALS_ENABLED"`
	StorePath       string `yaml:"store_path" env:"TRUVA_CREDENTIALS_STORE_PATH"`
	MasterPassword  string `yaml:"master_password" env:"TRUVA_CREDENTIALS_MASTER_PASSWORD"`
	RotationEnabled bool   `yaml:"rotation_enabled" env:"TRUVA_CREDENTIALS_ROTATION_ENABLED"`
	RotationHours   int    `yaml:"rotation_hours" env:"TRUVA_CREDENTIALS_ROTATION_HOURS"`
}

// SecretsConfig holds configuration for secrets management
type SecretsConfig struct {
	Enabled         bool   `yaml:"enabled" env:"TRUVA_SECRETS_ENABLED"`
	StorePath       string `yaml:"store_path" env:"TRUVA_SECRETS_STORE_PATH"`
	MasterPassword  string `yaml:"master_password" env:"TRUVA_SECRETS_MASTER_PASSWORD"`
	Encrypted       bool   `yaml:"encrypted" env:"TRUVA_SECRETS_ENCRYPTED"`
	AutoCleanup     bool   `yaml:"auto_cleanup" env:"TRUVA_SECRETS_AUTO_CLEANUP"`
	CleanupInterval int    `yaml:"cleanup_interval" env:"TRUVA_SECRETS_CLEANUP_INTERVAL"`
}

type CORSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool              `yaml:"enabled" env:"TRUVA_RATE_LIMIT_ENABLED"`
	RequestsPerMinute int               `yaml:"requests_per_minute" env:"TRUVA_RATE_LIMIT_REQUESTS_PER_MINUTE"`
	BurstSize         int               `yaml:"burst_size" env:"TRUVA_RATE_LIMIT_BURST_SIZE"`
	BlockDuration     time.Duration     `yaml:"block_duration" env:"TRUVA_RATE_LIMIT_BLOCK_DURATION"`
	Whitelist         []string          `yaml:"whitelist" env:"TRUVA_RATE_LIMIT_WHITELIST"`
	WebSocket         WSRateLimitConfig `yaml:"websocket"`
}

// WSRateLimitConfig holds WebSocket-specific rate limiting configuration
type WSRateLimitConfig struct {
	Enabled           bool          `yaml:"enabled" env:"TRUVA_WS_RATE_LIMIT_ENABLED"`
	MaxConnections    int           `yaml:"max_connections" env:"TRUVA_WS_RATE_LIMIT_MAX_CONNECTIONS"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout" env:"TRUVA_WS_RATE_LIMIT_CONNECTION_TIMEOUT"`
	Whitelist         []string      `yaml:"whitelist" env:"TRUVA_WS_RATE_LIMIT_WHITELIST"`
	MaxAge            int           `yaml:"max_age"`
}

var (
	GlobalConfig  *Config
	globalManager *ConfigManager
	managerMutex  sync.RWMutex
)

// NewConfigManager creates a new configuration manager
func NewConfigManager(environment Environment) *ConfigManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConfigManager{
		environment:     environment,
		configPaths:     []string{},
		validators:      []ConfigValidator{},
		changeCallbacks: []func(*Config){},
		ctx:             ctx,
		cancel:          cancel,
	}
}

// GetEnvironment returns the current environment from environment variable or default
func GetEnvironment() Environment {
	env := os.Getenv("TRUVA_ENV")
	if env == "" {
		env = os.Getenv("ENV")
	}
	if env == "" {
		env = os.Getenv("ENVIRONMENT")
	}

	switch Environment(strings.ToLower(env)) {
	case Development, Staging, Production, Testing:
		return Environment(strings.ToLower(env))
	default:
		return Development // Default to development
	}
}

// LoadConfig loads configuration with environment-specific overrides
func LoadConfig(configPath string) error {
	environment := GetEnvironment()
	manager := NewConfigManager(environment)

	// Set up configuration paths
	paths := manager.getConfigPaths(configPath)
	manager.configPaths = paths

	// Load configuration
	config, err := manager.loadConfigFromPaths(paths)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Apply environment variable overrides
	err = manager.applyEnvironmentOverrides(config)
	if err != nil {
		return fmt.Errorf("failed to apply environment overrides: %w", err)
	}

	// Set environment in config
	config.Environment = environment

	// Add default validators
	manager.AddValidator(validateServerConfig)
	manager.AddValidator(validateAuthConfig)
	manager.AddValidator(validateRateLimitConfig)

	// Validate configuration
	err = manager.validateConfig(config)
	if err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set global config and manager
	manager.config = config
	GlobalConfig = config

	managerMutex.Lock()
	globalManager = manager
	managerMutex.Unlock()

	return nil
}

// EnableHotReload enables hot reloading of configuration files
func EnableHotReload() error {
	managerMutex.RLock()
	manager := globalManager
	managerMutex.RUnlock()

	if manager == nil {
		return fmt.Errorf("configuration manager not initialized")
	}

	return manager.enableHotReload()
}

// AddValidator adds a configuration validator
func AddValidator(validator ConfigValidator) {
	managerMutex.RLock()
	manager := globalManager
	managerMutex.RUnlock()

	if manager != nil {
		manager.AddValidator(validator)
	}
}

// OnConfigChange adds a callback for configuration changes
func OnConfigChange(callback func(*Config)) {
	managerMutex.RLock()
	manager := globalManager
	managerMutex.RUnlock()

	if manager != nil {
		manager.OnConfigChange(callback)
	}
}

// getConfigPaths returns the list of configuration file paths to load
func (cm *ConfigManager) getConfigPaths(basePath string) []string {
	if basePath == "" {
		basePath = "config.yaml"
	}

	paths := []string{}

	// Base configuration file
	paths = append(paths, basePath)

	// Environment-specific configuration
	dir := filepath.Dir(basePath)
	name := strings.TrimSuffix(filepath.Base(basePath), filepath.Ext(basePath))
	ext := filepath.Ext(basePath)

	envConfigPath := filepath.Join(dir, fmt.Sprintf("%s.%s%s", name, cm.environment, ext))
	if _, err := os.Stat(envConfigPath); err == nil {
		paths = append(paths, envConfigPath)
	}

	// Local override configuration
	localConfigPath := filepath.Join(dir, fmt.Sprintf("%s.local%s", name, ext))
	if _, err := os.Stat(localConfigPath); err == nil {
		paths = append(paths, localConfigPath)
	}

	return paths
}

// loadConfigFromPaths loads and merges configuration from multiple files
func (cm *ConfigManager) loadConfigFromPaths(paths []string) (*Config, error) {
	config := cm.getDefaultConfig()

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue // Skip non-existent files
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}

		// Create a temporary config to unmarshal into
		tempConfig := &Config{}
		err = yaml.Unmarshal(data, tempConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
		}

		// Merge the temporary config into the main config
		err = cm.mergeConfigs(config, tempConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to merge config from %s: %w", path, err)
		}
	}

	return config, nil
}

// mergeConfigs merges source config into destination config
func (cm *ConfigManager) mergeConfigs(dst, src *Config) error {
	// Use reflection to merge non-zero values from src to dst
	dstValue := reflect.ValueOf(dst).Elem()
	srcValue := reflect.ValueOf(src).Elem()

	return cm.mergeStructs(dstValue, srcValue)
}

// mergeStructs recursively merges struct fields
func (cm *ConfigManager) mergeStructs(dst, src reflect.Value) error {
	for i := 0; i < src.NumField(); i++ {
		srcField := src.Field(i)
		dstField := dst.Field(i)

		if !srcField.IsValid() || !dstField.CanSet() {
			continue
		}

		switch srcField.Kind() {
		case reflect.Struct:
			err := cm.mergeStructs(dstField, srcField)
			if err != nil {
				return err
			}
		case reflect.Slice:
			if srcField.Len() > 0 {
				dstField.Set(srcField)
			}
		default:
			if !cm.isZeroValue(srcField) {
				dstField.Set(srcField)
			}
		}
	}
	return nil
}

// isZeroValue checks if a reflect.Value is the zero value for its type
func (cm *ConfigManager) isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	default:
		return false
	}
}

// applyEnvironmentOverrides applies environment variable overrides
func (cm *ConfigManager) applyEnvironmentOverrides(config *Config) error {
	return cm.applyEnvOverridesToStruct(reflect.ValueOf(config).Elem())
}

// applyEnvOverridesToStruct recursively applies environment overrides to struct fields
func (cm *ConfigManager) applyEnvOverridesToStruct(v reflect.Value) error {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		if !field.CanSet() {
			continue
		}

		// Check for env tag
		envTag := fieldType.Tag.Get("env")
		if envTag != "" {
			envValue := os.Getenv(envTag)
			if envValue != "" {
				err := cm.setFieldFromString(field, envValue)
				if err != nil {
					return fmt.Errorf("failed to set field %s from env %s: %w", fieldType.Name, envTag, err)
				}
			}
		}

		// Recursively process nested structs
		if field.Kind() == reflect.Struct {
			err := cm.applyEnvOverridesToStruct(field)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// setFieldFromString sets a field value from a string representation
func (cm *ConfigManager) setFieldFromString(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		field.SetBool(boolVal)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			duration, err := time.ParseDuration(value)
			if err != nil {
				return err
			}
			field.SetInt(int64(duration))
		} else {
			intVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return err
			}
			field.SetInt(intVal)
		}
	case reflect.Slice:
		if field.Type().Elem().Kind() == reflect.String {
			sliceVal := strings.Split(value, ",")
			for i, s := range sliceVal {
				sliceVal[i] = strings.TrimSpace(s)
			}
			field.Set(reflect.ValueOf(sliceVal))
		}
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}
	return nil
}

// AddValidator adds a configuration validator
func (cm *ConfigManager) AddValidator(validator ConfigValidator) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.validators = append(cm.validators, validator)
}

// OnConfigChange adds a callback for configuration changes
func (cm *ConfigManager) OnConfigChange(callback func(*Config)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.changeCallbacks = append(cm.changeCallbacks, callback)
}

// validateConfig validates the configuration using all registered validators
func (cm *ConfigManager) validateConfig(config *Config) error {
	var errors ValidationErrors

	for _, validator := range cm.validators {
		if err := validator(config); err != nil {
			if validationErr, ok := err.(ValidationError); ok {
				errors = append(errors, validationErr)
			} else if validationErrs, ok := err.(ValidationErrors); ok {
				errors = append(errors, validationErrs...)
			} else {
				errors = append(errors, ValidationError{Field: "unknown", Message: err.Error()})
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// enableHotReload enables hot reloading of configuration files
func (cm *ConfigManager) enableHotReload() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	cm.watcher = watcher

	// Watch all configuration files
	for _, path := range cm.configPaths {
		if _, err := os.Stat(path); err == nil {
			err = watcher.Add(path)
			if err != nil {
				return fmt.Errorf("failed to watch config file %s: %w", path, err)
			}
		}
	}

	// Start watching for changes
	go cm.watchConfigChanges()

	return nil
}

// watchConfigChanges watches for configuration file changes
func (cm *ConfigManager) watchConfigChanges() {
	for {
		select {
		case <-cm.ctx.Done():
			return
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write {
				// Reload configuration
				err := cm.reloadConfig()
				if err != nil {
					fmt.Printf("Failed to reload configuration: %v\n", err)
				}
			}
		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("Config watcher error: %v\n", err)
		}
	}
}

// reloadConfig reloads the configuration from files
func (cm *ConfigManager) reloadConfig() error {
	// Load new configuration
	newConfig, err := cm.loadConfigFromPaths(cm.configPaths)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Apply environment overrides
	err = cm.applyEnvironmentOverrides(newConfig)
	if err != nil {
		return fmt.Errorf("failed to apply environment overrides: %w", err)
	}

	// Set environment
	newConfig.Environment = cm.environment

	// Validate new configuration
	err = cm.validateConfig(newConfig)
	if err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Update configuration
	cm.mu.Lock()
	cm.config = newConfig
	GlobalConfig = newConfig
	cm.mu.Unlock()

	// Notify callbacks
	for _, callback := range cm.changeCallbacks {
		go callback(newConfig)
	}

	fmt.Printf("Configuration reloaded successfully (environment: %s)\n", cm.environment)
	return nil
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// Stop stops the configuration manager
func (cm *ConfigManager) Stop() {
	if cm.watcher != nil {
		cm.watcher.Close()
	}
	cm.cancel()
}

// Default validators

// validateServerConfig validates server configuration
func validateServerConfig(config *Config) error {
	var errors ValidationErrors

	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		errors = append(errors, ValidationError{
			Field:   "server.port",
			Message: "port must be between 1 and 65535",
		})
	}

	if config.Server.Host == "" {
		errors = append(errors, ValidationError{
			Field:   "server.host",
			Message: "host cannot be empty",
		})
	}

	if config.Server.TLS.Enabled {
		if config.Server.TLS.CertFile == "" {
			errors = append(errors, ValidationError{
				Field:   "server.tls.cert_file",
				Message: "cert_file is required when TLS is enabled",
			})
		}
		if config.Server.TLS.KeyFile == "" {
			errors = append(errors, ValidationError{
				Field:   "server.tls.key_file",
				Message: "key_file is required when TLS is enabled",
			})
		}
		if config.Server.TLS.HTTPSPort <= 0 || config.Server.TLS.HTTPSPort > 65535 {
			errors = append(errors, ValidationError{
				Field:   "server.tls.https_port",
				Message: "https_port must be between 1 and 65535",
			})
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateAuthConfig validates authentication configuration
func validateAuthConfig(config *Config) error {
	var errors ValidationErrors

	if config.Auth.Enabled {
		if config.Auth.JWTSecret == "" {
			errors = append(errors, ValidationError{
				Field:   "auth.jwt_secret",
				Message: "jwt_secret is required when auth is enabled",
			})
		}
		if config.Auth.TokenExpiry <= 0 {
			errors = append(errors, ValidationError{
				Field:   "auth.token_expiry",
				Message: "token_expiry must be positive",
			})
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateRateLimitConfig validates rate limiting configuration
func validateRateLimitConfig(config *Config) error {
	var errors ValidationErrors

	if config.RateLimit.Enabled {
		if config.RateLimit.RequestsPerMinute <= 0 {
			errors = append(errors, ValidationError{
				Field:   "rate_limit.requests_per_minute",
				Message: "requests_per_minute must be positive",
			})
		}
		if config.RateLimit.BurstSize <= 0 {
			errors = append(errors, ValidationError{
				Field:   "rate_limit.burst_size",
				Message: "burst_size must be positive",
			})
		}
		if config.RateLimit.BlockDuration <= 0 {
			errors = append(errors, ValidationError{
				Field:   "rate_limit.block_duration",
				Message: "block_duration must be positive",
			})
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// getDefaultConfig returns the default configuration for the environment
func (cm *ConfigManager) getDefaultConfig() *Config {
	templatePathDefault := getDefaultTemplatePath()

	baseConfig := &Config{
		Server: ServerConfig{
			Port: 8080,
			Host: "localhost",
			TLS: TLSConfig{
				Enabled:       false,
				CertFile:      "./certs/server.crt",
				KeyFile:       "./certs/server.key",
				AutoTLS:       false,
				HTTPSPort:     8443,
				RedirectHTTP:  true,
				MinTLSVersion: "1.2",
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			File:   "app.log",
			Format: "text",
		},
		UI: UIConfig{
			TemplatePath: templatePathDefault,
		},
		Sync: SyncConfig{
			DebounceDuration: "2s",
			BatchSize:        10,
		},
		Auth: AuthConfig{
			Enabled:        false,
			RequireAuth:    false,
			JWTSecret:      "",
			TokenExpiry:    24 * time.Hour,
			APIKeys:        []string{},
			AllowedOrigins: []string{"http://localhost:3000", "http://localhost:8080"},
			CORS: CORSConfig{
				Enabled:          true,
				AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:8080"},
				AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
				ExposedHeaders:   []string{"Content-Length"},
				AllowCredentials: true,
			},
		},
		Credentials: CredentialsConfig{
			Enabled:         false,
			StorePath:       "./credentials.enc",
			MasterPassword:  "change-me-in-production",
			RotationEnabled: false,
			RotationHours:   24,
		},
		Secrets: SecretsConfig{
			Enabled:         true,
			StorePath:       "./secrets.enc",
			MasterPassword:  "${env:TRUVA_SECRETS_MASTER_PASSWORD}",
			Encrypted:       true,
			AutoCleanup:     true,
			CleanupInterval: 24,
		},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerMinute: 60,
			BurstSize:         10,
			BlockDuration:     1 * time.Minute,
			Whitelist:         []string{"127.0.0.1", "::1"},
			WebSocket: WSRateLimitConfig{
				Enabled:           true,
				MaxConnections:    5,
				ConnectionTimeout: 1 * time.Hour,
				Whitelist:         []string{"127.0.0.1", "::1"},
			},
		},
		Environment: cm.environment,
	}

	// Environment-specific defaults
	switch cm.environment {
	case Production:
		baseConfig.Logging.Level = "warn"
		baseConfig.Server.TLS.Enabled = true
		baseConfig.Auth.Enabled = true
		baseConfig.Auth.RequireAuth = true
		baseConfig.Credentials.Enabled = true
		baseConfig.RateLimit.RequestsPerMinute = 120
		baseConfig.RateLimit.BurstSize = 20
	case Staging:
		baseConfig.Logging.Level = "debug"
		baseConfig.Auth.Enabled = true
		baseConfig.Credentials.Enabled = true
		baseConfig.RateLimit.RequestsPerMinute = 100
	case Testing:
		baseConfig.Logging.Level = "debug"
		baseConfig.Auth.Enabled = false
		baseConfig.RateLimit.Enabled = false
	case Development:
		baseConfig.Logging.Level = "debug"
		baseConfig.Auth.Enabled = false
		baseConfig.RateLimit.RequestsPerMinute = 1000
	}

	return baseConfig
}

// GetConfig returns the global configuration
func GetConfig() *Config {
	if GlobalConfig == nil {
		// Return default config if not loaded
		manager := NewConfigManager(GetEnvironment())
		GlobalConfig = manager.getDefaultConfig()
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

// GetDebounceDuration returns the parsed debounce duration
func (c *Config) GetDebounceDuration() time.Duration {
	duration, err := time.ParseDuration(c.Sync.DebounceDuration)
	if err != nil {
		return 2 * time.Second // default
	}
	return duration
}

// IsProduction returns true if the environment is production
func (c *Config) IsProduction() bool {
	return c.Environment == Production
}

// IsDevelopment returns true if the environment is development
func (c *Config) IsDevelopment() bool {
	return c.Environment == Development
}

// IsStaging returns true if the environment is staging
func (c *Config) IsStaging() bool {
	return c.Environment == Staging
}

// IsTesting returns true if the environment is testing
func (c *Config) IsTesting() bool {
	return c.Environment == Testing
}

// ValidateEnvironmentVariables validates that required environment variables are set
func ValidateEnvironmentVariables() error {
	var errors ValidationErrors

	env := GetEnvironment()

	// Production-specific validations
	if env == Production {
		if os.Getenv("TRUVA_SECRETS_MASTER_PASSWORD") == "" {
			errors = append(errors, ValidationError{
				Field:   "TRUVA_SECRETS_MASTER_PASSWORD",
				Message: "required in production environment",
			})
		}
		if os.Getenv("TRUVA_CREDENTIALS_MASTER_PASSWORD") == "" {
			errors = append(errors, ValidationError{
				Field:   "TRUVA_CREDENTIALS_MASTER_PASSWORD",
				Message: "required in production environment",
			})
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// ReloadConfig reloads the configuration
func ReloadConfig() error {
	managerMutex.RLock()
	manager := globalManager
	managerMutex.RUnlock()

	if manager == nil {
		return fmt.Errorf("configuration manager not initialized")
	}

	return manager.reloadConfig()
}

// StopConfigManager stops the global configuration manager
func StopConfigManager() {
	managerMutex.RLock()
	manager := globalManager
	managerMutex.RUnlock()

	if manager != nil {
		manager.Stop()
	}
}

// FeatureFlag represents a feature flag configuration
type FeatureFlag struct {
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Description string                 `yaml:"description" json:"description"`
	Rollout     FeatureRolloutConfig   `yaml:"rollout" json:"rollout"`
	Conditions  []FeatureCondition     `yaml:"conditions" json:"conditions"`
	Metadata    map[string]interface{} `yaml:"metadata" json:"metadata"`
}

// FeatureRolloutConfig defines rollout strategy for a feature
type FeatureRolloutConfig struct {
	Strategy   RolloutStrategy `yaml:"strategy" json:"strategy"`
	Percentage int             `yaml:"percentage" json:"percentage"`
	UserGroups []string        `yaml:"user_groups" json:"user_groups"`
	StartDate  *time.Time      `yaml:"start_date" json:"start_date"`
	EndDate    *time.Time      `yaml:"end_date" json:"end_date"`
}

// RolloutStrategy defines how a feature should be rolled out
type RolloutStrategy string

const (
	RolloutAll        RolloutStrategy = "all"
	RolloutPercentage RolloutStrategy = "percentage"
	RolloutUserGroups RolloutStrategy = "user_groups"
	RolloutScheduled  RolloutStrategy = "scheduled"
	RolloutABTest     RolloutStrategy = "ab_test"
)

// FeatureCondition defines conditions for feature activation
type FeatureCondition struct {
	Type     ConditionType `yaml:"type" json:"type"`
	Operator string        `yaml:"operator" json:"operator"`
	Value    interface{}   `yaml:"value" json:"value"`
	Field    string        `yaml:"field" json:"field"`
}

// ConditionType defines the type of condition
type ConditionType string

const (
	ConditionEnvironment ConditionType = "environment"
	ConditionUserID      ConditionType = "user_id"
	ConditionUserGroup   ConditionType = "user_group"
	ConditionIPAddress   ConditionType = "ip_address"
	ConditionUserAgent   ConditionType = "user_agent"
	ConditionCustom      ConditionType = "custom"
)

// FeatureFlagsConfig holds feature flags configuration
type FeatureFlagsConfig struct {
	Enabled         bool                   `yaml:"enabled" json:"enabled"`
	Flags           map[string]FeatureFlag `yaml:"flags" json:"flags"`
	RefreshInterval time.Duration          `yaml:"refresh_interval" json:"refresh_interval"`
	RemoteSource    string                 `yaml:"remote_source" json:"remote_source"`
}

// FeatureFlagManager manages feature flags
type FeatureFlagManager struct {
	mu              sync.RWMutex
	flags           map[string]FeatureFlag
	config          *FeatureFlagsConfig
	ctx             context.Context
	cancel          context.CancelFunc
	lastUpdate      time.Time
	changeCallbacks []func(string, bool)
}

// FeatureFlagContext provides context for feature flag evaluation
type FeatureFlagContext struct {
	UserID      string                 `json:"user_id"`
	UserGroups  []string               `json:"user_groups"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Environment Environment            `json:"environment"`
	Custom      map[string]interface{} `json:"custom"`
}

var (
	globalFeatureFlagManager *FeatureFlagManager
	featureFlagManagerMutex  sync.RWMutex
)

// NewFeatureFlagManager creates a new feature flag manager
func NewFeatureFlagManager(config *FeatureFlagsConfig) *FeatureFlagManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &FeatureFlagManager{
		flags:           make(map[string]FeatureFlag),
		config:          config,
		ctx:             ctx,
		cancel:          cancel,
		changeCallbacks: []func(string, bool){},
	}
}

// InitializeFeatureFlags initializes the global feature flag manager
func InitializeFeatureFlags(config *FeatureFlagsConfig) error {
	featureFlagManagerMutex.Lock()
	defer featureFlagManagerMutex.Unlock()

	if globalFeatureFlagManager != nil {
		globalFeatureFlagManager.Stop()
	}

	manager := NewFeatureFlagManager(config)
	err := manager.LoadFlags(config.Flags)
	if err != nil {
		return fmt.Errorf("failed to load feature flags: %w", err)
	}

	globalFeatureFlagManager = manager

	// Start refresh routine if enabled
	if config.RefreshInterval > 0 {
		go manager.startRefreshRoutine()
	}

	return nil
}

// LoadFlags loads feature flags into the manager
func (ffm *FeatureFlagManager) LoadFlags(flags map[string]FeatureFlag) error {
	ffm.mu.Lock()
	defer ffm.mu.Unlock()

	ffm.flags = make(map[string]FeatureFlag)
	for name, flag := range flags {
		// Validate flag configuration
		if err := ffm.validateFlag(name, flag); err != nil {
			return fmt.Errorf("invalid flag %s: %w", name, err)
		}
		ffm.flags[name] = flag
	}

	ffm.lastUpdate = time.Now()
	return nil
}

// validateFlag validates a feature flag configuration
func (ffm *FeatureFlagManager) validateFlag(name string, flag FeatureFlag) error {
	if name == "" {
		return fmt.Errorf("flag name cannot be empty")
	}

	// Validate rollout configuration
	if flag.Rollout.Strategy == RolloutPercentage {
		if flag.Rollout.Percentage < 0 || flag.Rollout.Percentage > 100 {
			return fmt.Errorf("percentage must be between 0 and 100")
		}
	}

	if flag.Rollout.Strategy == RolloutScheduled {
		if flag.Rollout.StartDate == nil {
			return fmt.Errorf("start_date is required for scheduled rollout")
		}
	}

	// Validate conditions
	for i, condition := range flag.Conditions {
		if condition.Type == "" {
			return fmt.Errorf("condition %d: type cannot be empty", i)
		}
		if condition.Operator == "" {
			return fmt.Errorf("condition %d: operator cannot be empty", i)
		}
	}

	return nil
}

// IsEnabled checks if a feature flag is enabled for the given context
func (ffm *FeatureFlagManager) IsEnabled(flagName string, ctx *FeatureFlagContext) bool {
	ffm.mu.RLock()
	defer ffm.mu.RUnlock()

	flag, exists := ffm.flags[flagName]
	if !exists {
		return false
	}

	// Check if flag is globally disabled
	if !flag.Enabled {
		return false
	}

	// Evaluate conditions
	if !ffm.evaluateConditions(flag.Conditions, ctx) {
		return false
	}

	// Evaluate rollout strategy
	return ffm.evaluateRollout(flag.Rollout, ctx)
}

// evaluateConditions evaluates all conditions for a flag
func (ffm *FeatureFlagManager) evaluateConditions(conditions []FeatureCondition, ctx *FeatureFlagContext) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, condition := range conditions {
		if !ffm.evaluateCondition(condition, ctx) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (ffm *FeatureFlagManager) evaluateCondition(condition FeatureCondition, ctx *FeatureFlagContext) bool {
	var fieldValue interface{}

	switch condition.Type {
	case ConditionEnvironment:
		fieldValue = string(ctx.Environment)
	case ConditionUserID:
		fieldValue = ctx.UserID
	case ConditionUserGroup:
		return ffm.evaluateUserGroupCondition(condition, ctx.UserGroups)
	case ConditionIPAddress:
		fieldValue = ctx.IPAddress
	case ConditionUserAgent:
		fieldValue = ctx.UserAgent
	case ConditionCustom:
		if ctx.Custom != nil {
			fieldValue = ctx.Custom[condition.Field]
		}
	default:
		return false
	}

	return ffm.evaluateOperator(condition.Operator, fieldValue, condition.Value)
}

// evaluateUserGroupCondition evaluates user group conditions
func (ffm *FeatureFlagManager) evaluateUserGroupCondition(condition FeatureCondition, userGroups []string) bool {
	expectedGroup, ok := condition.Value.(string)
	if !ok {
		return false
	}

	switch condition.Operator {
	case "in":
		for _, group := range userGroups {
			if group == expectedGroup {
				return true
			}
		}
		return false
	case "not_in":
		for _, group := range userGroups {
			if group == expectedGroup {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// evaluateOperator evaluates an operator condition
func (ffm *FeatureFlagManager) evaluateOperator(operator string, fieldValue, expectedValue interface{}) bool {
	switch operator {
	case "equals", "eq":
		return fieldValue == expectedValue
	case "not_equals", "ne":
		return fieldValue != expectedValue
	case "contains":
		fieldStr, ok1 := fieldValue.(string)
		expectedStr, ok2 := expectedValue.(string)
		if ok1 && ok2 {
			return strings.Contains(fieldStr, expectedStr)
		}
		return false
	case "starts_with":
		fieldStr, ok1 := fieldValue.(string)
		expectedStr, ok2 := expectedValue.(string)
		if ok1 && ok2 {
			return strings.HasPrefix(fieldStr, expectedStr)
		}
		return false
	case "regex":
		fieldStr, ok1 := fieldValue.(string)
		pattern, ok2 := expectedValue.(string)
		if ok1 && ok2 {
			matched, err := regexp.MatchString(pattern, fieldStr)
			return err == nil && matched
		}
		return false
	default:
		return false
	}
}

// evaluateRollout evaluates rollout strategy
func (ffm *FeatureFlagManager) evaluateRollout(rollout FeatureRolloutConfig, ctx *FeatureFlagContext) bool {
	switch rollout.Strategy {
	case RolloutAll:
		return true
	case RolloutPercentage:
		return ffm.evaluatePercentageRollout(rollout.Percentage, ctx.UserID)
	case RolloutUserGroups:
		return ffm.evaluateUserGroupsRollout(rollout.UserGroups, ctx.UserGroups)
	case RolloutScheduled:
		return ffm.evaluateScheduledRollout(rollout.StartDate, rollout.EndDate)
	case RolloutABTest:
		return ffm.evaluateABTestRollout(rollout.Percentage, ctx.UserID)
	default:
		return false
	}
}

// evaluatePercentageRollout evaluates percentage-based rollout
func (ffm *FeatureFlagManager) evaluatePercentageRollout(percentage int, userID string) bool {
	if userID == "" {
		return false
	}

	// Use consistent hashing to determine if user is in rollout
	hash := fnv.New32a()
	hash.Write([]byte(userID))
	userHash := hash.Sum32()

	return int(userHash%100) < percentage
}

// evaluateUserGroupsRollout evaluates user groups rollout
func (ffm *FeatureFlagManager) evaluateUserGroupsRollout(allowedGroups, userGroups []string) bool {
	for _, userGroup := range userGroups {
		for _, allowedGroup := range allowedGroups {
			if userGroup == allowedGroup {
				return true
			}
		}
	}
	return false
}

// evaluateScheduledRollout evaluates scheduled rollout
func (ffm *FeatureFlagManager) evaluateScheduledRollout(startDate, endDate *time.Time) bool {
	now := time.Now()

	if startDate != nil && now.Before(*startDate) {
		return false
	}

	if endDate != nil && now.After(*endDate) {
		return false
	}

	return true
}

// evaluateABTestRollout evaluates A/B test rollout
func (ffm *FeatureFlagManager) evaluateABTestRollout(percentage int, userID string) bool {
	// Similar to percentage rollout but with different hashing for A/B testing
	if userID == "" {
		return false
	}

	hash := fnv.New32a()
	hash.Write([]byte("ab_test_" + userID))
	userHash := hash.Sum32()

	return int(userHash%100) < percentage
}

// OnFlagChange adds a callback for flag changes
func (ffm *FeatureFlagManager) OnFlagChange(callback func(string, bool)) {
	ffm.mu.Lock()
	defer ffm.mu.Unlock()
	ffm.changeCallbacks = append(ffm.changeCallbacks, callback)
}

// UpdateFlag updates a feature flag
func (ffm *FeatureFlagManager) UpdateFlag(name string, flag FeatureFlag) error {
	ffm.mu.Lock()
	defer ffm.mu.Unlock()

	if err := ffm.validateFlag(name, flag); err != nil {
		return err
	}

	oldFlag, existed := ffm.flags[name]
	ffm.flags[name] = flag

	// Notify callbacks if flag state changed
	if !existed || oldFlag.Enabled != flag.Enabled {
		for _, callback := range ffm.changeCallbacks {
			go callback(name, flag.Enabled)
		}
	}

	return nil
}

// GetFlag returns a feature flag by name
func (ffm *FeatureFlagManager) GetFlag(name string) (FeatureFlag, bool) {
	ffm.mu.RLock()
	defer ffm.mu.RUnlock()

	flag, exists := ffm.flags[name]
	return flag, exists
}

// GetAllFlags returns all feature flags
func (ffm *FeatureFlagManager) GetAllFlags() map[string]FeatureFlag {
	ffm.mu.RLock()
	defer ffm.mu.RUnlock()

	result := make(map[string]FeatureFlag)
	for name, flag := range ffm.flags {
		result[name] = flag
	}
	return result
}

// startRefreshRoutine starts the refresh routine for remote flags
func (ffm *FeatureFlagManager) startRefreshRoutine() {
	ticker := time.NewTicker(ffm.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ffm.ctx.Done():
			return
		case <-ticker.C:
			if ffm.config.RemoteSource != "" {
				ffm.refreshFromRemote()
			}
		}
	}
}

// refreshFromRemote refreshes flags from remote source
func (ffm *FeatureFlagManager) refreshFromRemote() {
	// Implementation would depend on the remote source type
	// This is a placeholder for remote flag fetching
	fmt.Printf("Refreshing feature flags from remote source: %s\n", ffm.config.RemoteSource)
}

// Stop stops the feature flag manager
func (ffm *FeatureFlagManager) Stop() {
	ffm.cancel()
}

// Global functions for feature flag operations

// IsFeatureEnabled checks if a feature is enabled globally
func IsFeatureEnabled(flagName string, ctx *FeatureFlagContext) bool {
	featureFlagManagerMutex.RLock()
	manager := globalFeatureFlagManager
	featureFlagManagerMutex.RUnlock()

	if manager == nil {
		return false
	}

	return manager.IsEnabled(flagName, ctx)
}

// UpdateFeatureFlag updates a feature flag globally
func UpdateFeatureFlag(name string, flag FeatureFlag) error {
	featureFlagManagerMutex.RLock()
	manager := globalFeatureFlagManager
	featureFlagManagerMutex.RUnlock()

	if manager == nil {
		return fmt.Errorf("feature flag manager not initialized")
	}

	return manager.UpdateFlag(name, flag)
}

// GetFeatureFlag returns a feature flag globally
func GetFeatureFlag(name string) (FeatureFlag, bool) {
	featureFlagManagerMutex.RLock()
	manager := globalFeatureFlagManager
	featureFlagManagerMutex.RUnlock()

	if manager == nil {
		return FeatureFlag{}, false
	}

	return manager.GetFlag(name)
}

// GetAllFeatureFlags returns all feature flags globally
func GetAllFeatureFlags() map[string]FeatureFlag {
	featureFlagManagerMutex.RLock()
	manager := globalFeatureFlagManager
	featureFlagManagerMutex.RUnlock()

	if manager == nil {
		return make(map[string]FeatureFlag)
	}

	return manager.GetAllFlags()
}

// OnFeatureFlagChange adds a global callback for flag changes
func OnFeatureFlagChange(callback func(string, bool)) {
	featureFlagManagerMutex.RLock()
	manager := globalFeatureFlagManager
	featureFlagManagerMutex.RUnlock()

	if manager != nil {
		manager.OnFlagChange(callback)
	}
}

// StopFeatureFlagManager stops the global feature flag manager
func StopFeatureFlagManager() {
	featureFlagManagerMutex.Lock()
	defer featureFlagManagerMutex.Unlock()

	if globalFeatureFlagManager != nil {
		globalFeatureFlagManager.Stop()
		globalFeatureFlagManager = nil
	}
}
