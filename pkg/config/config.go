// Package config provides configuration management for GoLEM.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Version     string           `json:"version" yaml:"version" mapstructure:"version"`
	Environment string           `json:"environment" yaml:"environment" mapstructure:"environment"`
	Debug       bool             `json:"debug" yaml:"debug" mapstructure:"debug"`
	LogLevel    string           `json:"log_level" yaml:"log_level" mapstructure:"log_level"`
	Engine      EngineConfig     `json:"engine" yaml:"engine" mapstructure:"engine"`
	REST        RESTConfig       `json:"rest" yaml:"rest" mapstructure:"rest"`
	LLM         LLMConfig        `json:"llm" yaml:"llm" mapstructure:"llm"`
	Memory      MemoryConfig     `json:"memory" yaml:"memory" mapstructure:"memory"`
	Tools       ToolsConfig      `json:"tools" yaml:"tools" mapstructure:"tools"`
	Security    SecurityConfig   `json:"security" yaml:"security" mapstructure:"security"`
	Monitoring  MonitoringConfig `json:"monitoring" yaml:"monitoring" mapstructure:"monitoring"`
}

type EngineConfig struct {
	WorkerCount   int  `json:"worker_count" yaml:"worker_count" mapstructure:"worker_count"`
	QueueSize     int  `json:"queue_size" yaml:"queue_size" mapstructure:"queue_size"`
	EnableMetrics bool `json:"enable_metrics" yaml:"enable_metrics" mapstructure:"enable_metrics"`
	TaskTimeout   int  `json:"task_timeout" yaml:"task_timeout" mapstructure:"task_timeout"` // seconds
	RetryAttempts int  `json:"retry_attempts" yaml:"retry_attempts" mapstructure:"retry_attempts"`
	RetryDelay    int  `json:"retry_delay" yaml:"retry_delay" mapstructure:"retry_delay"` // seconds
}

type RESTConfig struct {
	Port          int              `json:"port" yaml:"port" mapstructure:"port"`
	Host          string           `json:"host" yaml:"host" mapstructure:"host"`
	EnableCORS    bool             `json:"enable_cors" yaml:"enable_cors" mapstructure:"enable_cors"`
	CORSOrigins   []string         `json:"cors_origins" yaml:"cors_origins" mapstructure:"cors_origins"`
	EnableSwagger bool             `json:"enable_swagger" yaml:"enable_swagger" mapstructure:"enable_swagger"`
	EnableTLS     bool             `json:"enable_tls" yaml:"enable_tls" mapstructure:"enable_tls"`
	TLSCertFile   string           `json:"tls_cert_file" yaml:"tls_cert_file" mapstructure:"tls_cert_file"`
	TLSKeyFile    string           `json:"tls_key_file" yaml:"tls_key_file" mapstructure:"tls_key_file"`
	RateLimit     RateLimitConfig  `json:"rate_limit" yaml:"rate_limit" mapstructure:"rate_limit"`
	Middleware    MiddlewareConfig `json:"middleware" yaml:"middleware" mapstructure:"middleware"`
	Auth          AuthConfig       `json:"auth" yaml:"auth" mapstructure:"auth"`
}

type LLMConfig struct {
	DefaultProvider string                    `json:"default_provider" yaml:"default_provider" mapstructure:"default_provider"`
	Providers       map[string]ProviderConfig `json:"providers" yaml:"providers" mapstructure:"providers"`
}

type ProviderConfig struct {
	Enabled          bool              `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	APIKey           string            `json:"api_key" yaml:"api_key" mapstructure:"api_key"`
	BaseURL          string            `json:"base_url" yaml:"base_url" mapstructure:"base_url"`
	DefaultModel     string            `json:"default_model" yaml:"default_model" mapstructure:"default_model"`
	MaxTokens        int               `json:"max_tokens" yaml:"max_tokens" mapstructure:"max_tokens"`
	Temperature      float64           `json:"temperature" yaml:"temperature" mapstructure:"temperature"`
	TopP             float64           `json:"top_p" yaml:"top_p" mapstructure:"top_p"`
	FrequencyPenalty float64           `json:"frequency_penalty" yaml:"frequency_penalty" mapstructure:"frequency_penalty"`
	PresencePenalty  float64           `json:"presence_penalty" yaml:"presence_penalty" mapstructure:"presence_penalty"`
	RequestTimeout   int               `json:"request_timeout" yaml:"request_timeout" mapstructure:"request_timeout"` // seconds
	MaxRetries       int               `json:"max_retries" yaml:"max_retries" mapstructure:"max_retries"`
	CustomHeaders    map[string]string `json:"custom_headers" yaml:"custom_headers" mapstructure:"custom_headers"`
}

type MemoryConfig struct {
	DefaultBackend string                   `json:"default_backend" yaml:"default_backend" mapstructure:"default_backend"`
	Backends       map[string]BackendConfig `json:"backends" yaml:"backends" mapstructure:"backends"`
}

type BackendConfig struct {
	Type    string                 `json:"type" yaml:"type" mapstructure:"type"` // inmemory, redis, postgresql, sqlite
	Enabled bool                   `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	Config  map[string]interface{} `json:"config" yaml:"config" mapstructure:"config"`
}

type RedisConfig struct {
	Host         string `json:"host" yaml:"host" mapstructure:"host"`
	Port         int    `json:"port" yaml:"port" mapstructure:"port"`
	Password     string `json:"password" yaml:"password" mapstructure:"password"`
	Database     int    `json:"database" yaml:"database" mapstructure:"database"`
	PoolSize     int    `json:"pool_size" yaml:"pool_size" mapstructure:"pool_size"`
	MaxRetries   int    `json:"max_retries" yaml:"max_retries" mapstructure:"max_retries"`
	DialTimeout  int    `json:"dial_timeout" yaml:"dial_timeout" mapstructure:"dial_timeout"`
	ReadTimeout  int    `json:"read_timeout" yaml:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout int    `json:"write_timeout" yaml:"write_timeout" mapstructure:"write_timeout"`
}

type PostgreSQLConfig struct {
	Host         string `json:"host" yaml:"host" mapstructure:"host"`
	Port         int    `json:"port" yaml:"port" mapstructure:"port"`
	User         string `json:"user" yaml:"user" mapstructure:"user"`
	Password     string `json:"password" yaml:"password" mapstructure:"password"`
	Database     string `json:"database" yaml:"database" mapstructure:"database"`
	SSLMode      string `json:"ssl_mode" yaml:"ssl_mode" mapstructure:"ssl_mode"`
	MaxOpenConns int    `json:"max_open_conns" yaml:"max_open_conns" mapstructure:"max_open_conns"`
	MaxIdleConns int    `json:"max_idle_conns" yaml:"max_idle_conns" mapstructure:"max_idle_conns"`
	ConnLifetime int    `json:"conn_lifetime" yaml:"conn_lifetime" mapstructure:"conn_lifetime"`
}

type SQLiteConfig struct {
	Path        string `json:"path" yaml:"path" mapstructure:"path"`
	Mode        string `json:"mode" yaml:"mode" mapstructure:"mode"`
	CacheMode   string `json:"cache_mode" yaml:"cache_mode" mapstructure:"cache_mode"`
	JournalMode string `json:"journal_mode" yaml:"journal_mode" mapstructure:"journal_mode"`
	Synchronous string `json:"synchronous" yaml:"synchronous" mapstructure:"synchronous"`
	ForeignKeys bool   `json:"foreign_keys" yaml:"foreign_keys" mapstructure:"foreign_keys"`
	BusyTimeout int    `json:"busy_timeout" yaml:"busy_timeout" mapstructure:"busy_timeout"`
}

type ToolsConfig struct {
	EnabledTools  []string              `json:"enabled_tools" yaml:"enabled_tools" mapstructure:"enabled_tools"`
	DisabledTools []string              `json:"disabled_tools" yaml:"disabled_tools" mapstructure:"disabled_tools"`
	ToolConfigs   map[string]ToolConfig `json:"tool_configs" yaml:"tool_configs" mapstructure:"tool_configs"`
	Safety        SafetyConfig          `json:"safety" yaml:"safety" mapstructure:"safety"`
	Execution     ToolExecutionConfig   `json:"execution" yaml:"execution" mapstructure:"execution"`
}

type ToolConfig struct {
	Enabled    bool                   `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	Config     map[string]interface{} `json:"config" yaml:"config" mapstructure:"config"`
	Timeout    int                    `json:"timeout" yaml:"timeout" mapstructure:"timeout"` // seconds
	MaxRetries int                    `json:"max_retries" yaml:"max_retries" mapstructure:"max_retries"`
}

type SafetyConfig struct {
	EnableSandbox      bool     `json:"enable_sandbox" yaml:"enable_sandbox" mapstructure:"enable_sandbox"`
	AllowedPaths       []string `json:"allowed_paths" yaml:"allowed_paths" mapstructure:"allowed_paths"`
	BlockedPaths       []string `json:"blocked_paths" yaml:"blocked_paths" mapstructure:"blocked_paths"`
	AllowNetworkAccess bool     `json:"allow_network_access" yaml:"allow_network_access" mapstructure:"allow_network_access"`
	AllowedDomains     []string `json:"allowed_domains" yaml:"allowed_domains" mapstructure:"allowed_domains"`
	BlockedDomains     []string `json:"blocked_domains" yaml:"blocked_domains" mapstructure:"blocked_domains"`
	MaxFileSize        int64    `json:"max_file_size" yaml:"max_file_size" mapstructure:"max_file_size"`                // bytes
	MaxExecutionTime   int      `json:"max_execution_time" yaml:"max_execution_time" mapstructure:"max_execution_time"` // seconds
}

type ToolExecutionConfig struct {
	EnableParallel      bool `json:"enable_parallel" yaml:"enable_parallel" mapstructure:"enable_parallel"`
	MaxConcurrentTools  int  `json:"max_concurrent_tools" yaml:"max_concurrent_tools" mapstructure:"max_concurrent_tools"`
	GlobalTimeout       int  `json:"global_timeout" yaml:"global_timeout" mapstructure:"global_timeout"` // seconds
	EnableResultCaching bool `json:"enable_result_caching" yaml:"enable_result_caching" mapstructure:"enable_result_caching"`
	CacheTTL            int  `json:"cache_ttl" yaml:"cache_ttl" mapstructure:"cache_ttl"` // seconds
}

type SecurityConfig struct {
	EnableAuth     bool           `json:"enable_auth" yaml:"enable_auth" mapstructure:"enable_auth"`
	JWTSecret      string         `json:"jwt_secret" yaml:"jwt_secret" mapstructure:"jwt_secret"`
	JWTExpiration  int            `json:"jwt_expiration" yaml:"jwt_expiration" mapstructure:"jwt_expiration"` // hours
	APIKeys        []APIKeyConfig `json:"api_keys" yaml:"api_keys" mapstructure:"api_keys"`
	EnableHTTPS    bool           `json:"enable_https" yaml:"enable_https" mapstructure:"enable_https"`
	TrustedProxies []string       `json:"trusted_proxies" yaml:"trusted_proxies" mapstructure:"trusted_proxies"`
	EnableCSRF     bool           `json:"enable_csrf" yaml:"enable_csrf" mapstructure:"enable_csrf"`
	CSRFSecret     string         `json:"csrf_secret" yaml:"csrf_secret" mapstructure:"csrf_secret"`
	SessionConfig  SessionConfig  `json:"session" yaml:"session" mapstructure:"session"`
}

type APIKeyConfig struct {
	Key         string   `json:"key" yaml:"key" mapstructure:"key"`
	Name        string   `json:"name" yaml:"name" mapstructure:"name"`
	Permissions []string `json:"permissions" yaml:"permissions" mapstructure:"permissions"`
	Enabled     bool     `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	ExpiresAt   string   `json:"expires_at" yaml:"expires_at" mapstructure:"expires_at"`
}

type SessionConfig struct {
	Store    string `json:"store" yaml:"store" mapstructure:"store"` // memory, redis, cookie
	Secret   string `json:"secret" yaml:"secret" mapstructure:"secret"`
	MaxAge   int    `json:"max_age" yaml:"max_age" mapstructure:"max_age"` // seconds
	HTTPOnly bool   `json:"http_only" yaml:"http_only" mapstructure:"http_only"`
	Secure   bool   `json:"secure" yaml:"secure" mapstructure:"secure"`
	SameSite string `json:"same_site" yaml:"same_site" mapstructure:"same_site"`
	Domain   string `json:"domain" yaml:"domain" mapstructure:"domain"`
	Path     string `json:"path" yaml:"path" mapstructure:"path"`
}

type RateLimitConfig struct {
	Enabled           bool   `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	RequestsPerMinute int    `json:"requests_per_minute" yaml:"requests_per_minute" mapstructure:"requests_per_minute"`
	BurstSize         int    `json:"burst_size" yaml:"burst_size" mapstructure:"burst_size"`
	Store             string `json:"store" yaml:"store" mapstructure:"store"` // memory, redis
}

type MiddlewareConfig struct {
	EnableLogging     bool `json:"enable_logging" yaml:"enable_logging" mapstructure:"enable_logging"`
	EnableRecovery    bool `json:"enable_recovery" yaml:"enable_recovery" mapstructure:"enable_recovery"`
	EnableCompression bool `json:"enable_compression" yaml:"enable_compression" mapstructure:"enable_compression"`
	EnableTimeout     bool `json:"enable_timeout" yaml:"enable_timeout" mapstructure:"enable_timeout"`
	TimeoutDuration   int  `json:"timeout_duration" yaml:"timeout_duration" mapstructure:"timeout_duration"` // seconds
}

type AuthConfig struct {
	Provider       string            `json:"provider" yaml:"provider" mapstructure:"provider"` // jwt, oauth2, basic
	RequireAuth    bool              `json:"require_auth" yaml:"require_auth" mapstructure:"require_auth"`
	PublicPaths    []string          `json:"public_paths" yaml:"public_paths" mapstructure:"public_paths"`
	AdminPaths     []string          `json:"admin_paths" yaml:"admin_paths" mapstructure:"admin_paths"`
	OAuth2Config   OAuth2Config      `json:"oauth2" yaml:"oauth2" mapstructure:"oauth2"`
	BasicAuthUsers map[string]string `json:"basic_auth_users" yaml:"basic_auth_users" mapstructure:"basic_auth_users"`
}

type OAuth2Config struct {
	ClientID     string   `json:"client_id" yaml:"client_id" mapstructure:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret" mapstructure:"client_secret"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url" mapstructure:"redirect_url"`
	Scopes       []string `json:"scopes" yaml:"scopes" mapstructure:"scopes"`
	AuthURL      string   `json:"auth_url" yaml:"auth_url" mapstructure:"auth_url"`
	TokenURL     string   `json:"token_url" yaml:"token_url" mapstructure:"token_url"`
}

type MonitoringConfig struct {
	EnableMetrics    bool             `json:"enable_metrics" yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableTracing    bool             `json:"enable_tracing" yaml:"enable_tracing" mapstructure:"enable_tracing"`
	EnableProfiling  bool             `json:"enable_profiling" yaml:"enable_profiling" mapstructure:"enable_profiling"`
	MetricsPort      int              `json:"metrics_port" yaml:"metrics_port" mapstructure:"metrics_port"`
	PrometheusConfig PrometheusConfig `json:"prometheus" yaml:"prometheus" mapstructure:"prometheus"`
	JaegerConfig     JaegerConfig     `json:"jaeger" yaml:"jaeger" mapstructure:"jaeger"`
	HealthCheck      HealthConfig     `json:"health_check" yaml:"health_check" mapstructure:"health_check"`
}

type PrometheusConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	Path      string `json:"path" yaml:"path" mapstructure:"path"`
	Namespace string `json:"namespace" yaml:"namespace" mapstructure:"namespace"`
	Subsystem string `json:"subsystem" yaml:"subsystem" mapstructure:"subsystem"`
}

type JaegerConfig struct {
	Enabled       bool    `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	ServiceName   string  `json:"service_name" yaml:"service_name" mapstructure:"service_name"`
	AgentEndpoint string  `json:"agent_endpoint" yaml:"agent_endpoint" mapstructure:"agent_endpoint"`
	SamplerType   string  `json:"sampler_type" yaml:"sampler_type" mapstructure:"sampler_type"`
	SamplerParam  float64 `json:"sampler_param" yaml:"sampler_param" mapstructure:"sampler_param"`
}

type HealthConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled" mapstructure:"enabled"`
	Path       string `json:"path" yaml:"path" mapstructure:"path"`
	Interval   int    `json:"interval" yaml:"interval" mapstructure:"interval"`          // seconds
	Timeout    int    `json:"timeout" yaml:"timeout" mapstructure:"timeout"`             // seconds
	StartDelay int    `json:"start_delay" yaml:"start_delay" mapstructure:"start_delay"` // seconds
}

type ConfigManager struct {
	config *Config
	viper  *viper.Viper
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	v := viper.New()

	// Set default values
	setDefaults(v)

	return &ConfigManager{
		config: &Config{},
		viper:  v,
	}
}

// Load loads configuration from file and environment variables
func (cm *ConfigManager) Load(configPath string) error {
	if configPath != "" {
		cm.viper.SetConfigFile(configPath)
	} else {
		cm.viper.SetConfigName("golem")
		cm.viper.SetConfigType("yaml")
		cm.viper.AddConfigPath(".")
		cm.viper.AddConfigPath("./config")
		cm.viper.AddConfigPath("$HOME/.golem")
		cm.viper.AddConfigPath("/etc/golem")
	}

	cm.viper.AutomaticEnv()
	cm.viper.SetEnvPrefix("GOLEM")
	cm.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := cm.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Printf("No config file found, using defaults and environment variables\n")
		} else {
			return fmt.Errorf("error reading config file: %w", err)
		}
	} else {
		fmt.Printf("Using config file: %s\n", cm.viper.ConfigFileUsed())
	}

	if err := cm.viper.Unmarshal(cm.config); err != nil {
		return fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := cm.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// Get returns the current configuration
func (cm *ConfigManager) Get() *Config {
	return cm.config
}

// GetViper returns the viper instance for advanced usage
func (cm *ConfigManager) GetViper() *viper.Viper {
	return cm.viper
}

// Save saves the current configuration to a file
func (cm *ConfigManager) Save(path string) error {
	data, err := yaml.Marshal(cm.config)
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("error creating config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}

// Validate validates the configuration
func (cm *ConfigManager) Validate() error {
	config := cm.config
	if config.Engine.WorkerCount <= 0 {
		return fmt.Errorf("engine.worker_count must be greater than 0")
	}
	if config.Engine.QueueSize <= 0 {
		return fmt.Errorf("engine.queue_size must be greater than 0")
	}

	if config.REST.Port <= 0 || config.REST.Port > 65535 {
		return fmt.Errorf("rest.port must be between 1 and 65535")
	}

	if config.LLM.DefaultProvider == "" {
		return fmt.Errorf("llm.default_provider is required")
	}
	if _, exists := config.LLM.Providers[config.LLM.DefaultProvider]; !exists {
		return fmt.Errorf("llm.default_provider '%s' not found in providers", config.LLM.DefaultProvider)
	}

	if config.Memory.DefaultBackend == "" {
		return fmt.Errorf("memory.default_backend is required")
	}
	if _, exists := config.Memory.Backends[config.Memory.DefaultBackend]; !exists {
		return fmt.Errorf("memory.default_backend '%s' not found in backends", config.Memory.DefaultBackend)
	}

	return nil
}

// GenerateDefaultConfig generates a default configuration file
func GenerateDefaultConfig(path string) error {
	config := getDefaultConfig()

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshaling default config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("error creating config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing default config file: %w", err)
	}

	return nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	v.SetDefault("version", "1.0.0")
	v.SetDefault("environment", "development")
	v.SetDefault("debug", false)
	v.SetDefault("log_level", "info")

	v.SetDefault("engine.worker_count", 4)
	v.SetDefault("engine.queue_size", 100)
	v.SetDefault("engine.enable_metrics", true)
	v.SetDefault("engine.task_timeout", 300)
	v.SetDefault("engine.retry_attempts", 3)
	v.SetDefault("engine.retry_delay", 5)

	v.SetDefault("rest.port", 8080)
	v.SetDefault("rest.host", "0.0.0.0")
	v.SetDefault("rest.enable_cors", true)
	v.SetDefault("rest.cors_origins", []string{"*"})
	v.SetDefault("rest.enable_swagger", true)
	v.SetDefault("rest.enable_tls", false)
	v.SetDefault("rest.rate_limit.enabled", true)
	v.SetDefault("rest.rate_limit.requests_per_minute", 100)
	v.SetDefault("rest.rate_limit.burst_size", 10)
	v.SetDefault("rest.middleware.enable_logging", true)
	v.SetDefault("rest.middleware.enable_recovery", true)
	v.SetDefault("rest.middleware.enable_compression", true)
	v.SetDefault("rest.middleware.enable_timeout", true)
	v.SetDefault("rest.middleware.timeout_duration", 30)

	v.SetDefault("llm.default_provider", "openai")

	v.SetDefault("memory.default_backend", "inmemory")

	v.SetDefault("tools.enabled_tools", []string{"calculator", "search", "wikipedia", "filesystem", "http", "datetime", "text", "system"})
	v.SetDefault("tools.safety.enable_sandbox", true)
	v.SetDefault("tools.safety.allow_network_access", true)
	v.SetDefault("tools.safety.max_file_size", 1048576) // 1MB
	v.SetDefault("tools.safety.max_execution_time", 30)
	v.SetDefault("tools.execution.enable_parallel", true)
	v.SetDefault("tools.execution.max_concurrent_tools", 5)
	v.SetDefault("tools.execution.global_timeout", 60)
	v.SetDefault("tools.execution.enable_result_caching", true)
	v.SetDefault("tools.execution.cache_ttl", 300)

	v.SetDefault("security.enable_auth", false)
	v.SetDefault("security.jwt_expiration", 24)
	v.SetDefault("security.enable_https", false)
	v.SetDefault("security.enable_csrf", false)

	v.SetDefault("monitoring.enable_metrics", true)
	v.SetDefault("monitoring.enable_tracing", false)
	v.SetDefault("monitoring.enable_profiling", false)
	v.SetDefault("monitoring.metrics_port", 9091)
	v.SetDefault("monitoring.prometheus.enabled", true)
	v.SetDefault("monitoring.prometheus.path", "/metrics")
	v.SetDefault("monitoring.prometheus.namespace", "golem")
	v.SetDefault("monitoring.health_check.enabled", true)
	v.SetDefault("monitoring.health_check.path", "/health")
	v.SetDefault("monitoring.health_check.interval", 30)
	v.SetDefault("monitoring.health_check.timeout", 5)
}

// getDefaultConfig returns a default configuration structure
func getDefaultConfig() *Config {
	return &Config{
		Version:     "1.0.0",
		Environment: "development",
		Debug:       false,
		LogLevel:    "info",
		Engine: EngineConfig{
			WorkerCount:   4,
			QueueSize:     100,
			EnableMetrics: true,
			TaskTimeout:   300,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
		REST: RESTConfig{
			Port:          8080,
			Host:          "0.0.0.0",
			EnableCORS:    true,
			CORSOrigins:   []string{"*"},
			EnableSwagger: true,
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 100,
				BurstSize:         10,
				Store:             "memory",
			},
			Middleware: MiddlewareConfig{
				EnableLogging:     true,
				EnableRecovery:    true,
				EnableCompression: true,
				EnableTimeout:     true,
				TimeoutDuration:   30,
			},
		},
		LLM: LLMConfig{
			DefaultProvider: "openai",
			Providers: map[string]ProviderConfig{
				"openai": {
					Enabled:        false,
					DefaultModel:   "gpt-3.5-turbo",
					MaxTokens:      4096,
					Temperature:    0.7,
					RequestTimeout: 30,
					MaxRetries:     3,
				},
				"anthropic": {
					Enabled:        false,
					DefaultModel:   "claude-3-haiku",
					MaxTokens:      100000,
					Temperature:    0.7,
					RequestTimeout: 30,
					MaxRetries:     3,
				},
				"ollama": {
					Enabled:        false,
					BaseURL:        "http://localhost:11434",
					DefaultModel:   "llama2",
					RequestTimeout: 60,
					MaxRetries:     3,
				},
			},
		},
		Memory: MemoryConfig{
			DefaultBackend: "inmemory",
			Backends: map[string]BackendConfig{
				"inmemory": {
					Type:    "inmemory",
					Enabled: true,
				},
				"redis": {
					Type:    "redis",
					Enabled: false,
					Config: map[string]interface{}{
						"host":     "localhost",
						"port":     6379,
						"password": "",
						"database": 0,
					},
				},
			},
		},
		Tools: ToolsConfig{
			EnabledTools: []string{"calculator", "search", "wikipedia", "filesystem", "http", "datetime", "text", "system"},
			Safety: SafetyConfig{
				EnableSandbox:      true,
				AllowNetworkAccess: true,
				MaxFileSize:        1024 * 1024, // 1MB
				MaxExecutionTime:   30,
			},
			Execution: ToolExecutionConfig{
				EnableParallel:      true,
				MaxConcurrentTools:  5,
				GlobalTimeout:       60,
				EnableResultCaching: true,
				CacheTTL:            300,
			},
		},
		Security: SecurityConfig{
			EnableAuth:    false,
			JWTExpiration: 24,
		},
		Monitoring: MonitoringConfig{
			EnableMetrics:   true,
			EnableTracing:   false,
			EnableProfiling: false,
			MetricsPort:     9091,
			PrometheusConfig: PrometheusConfig{
				Enabled:   true,
				Path:      "/metrics",
				Namespace: "golem",
			},
			HealthCheck: HealthConfig{
				Enabled:  true,
				Path:     "/health",
				Interval: 30,
				Timeout:  5,
			},
		},
	}
}
