// Package llm provides the base interfaces and types for LLM providers.
package llm

import (
	"fmt"

	"github.com/astrica1/GoLEM/pkg/golem"
)

type ProviderType int

const (
	ProviderTypeOpenAI ProviderType = iota
	ProviderTypeAnthropic
	ProviderTypeOllama
	ProviderTypeCustom
)

// String returns the string representation of the provider type
func (pt ProviderType) String() string {
	switch pt {
	case ProviderTypeOpenAI:
		return "openai"
	case ProviderTypeAnthropic:
		return "anthropic"
	case ProviderTypeOllama:
		return "ollama"
	case ProviderTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

type BaseProvider struct {
	name            string
	providerType    ProviderType
	config          map[string]interface{}
	defaultModel    string
	supportedModels []golem.Model
}

// NewBaseProvider creates a new base provider
func NewBaseProvider(name string, providerType ProviderType) *BaseProvider {
	return &BaseProvider{
		name:            name,
		providerType:    providerType,
		config:          make(map[string]interface{}),
		supportedModels: make([]golem.Model, 0),
	}
}

// Name returns the provider name
func (bp *BaseProvider) Name() string {
	return bp.name
}

// GetProviderType returns the provider type
func (bp *BaseProvider) GetProviderType() ProviderType {
	return bp.providerType
}

// SetConfig sets the provider configuration
func (bp *BaseProvider) SetConfig(config map[string]interface{}) {
	bp.config = config
}

// GetConfig returns the provider configuration
func (bp *BaseProvider) GetConfig() map[string]interface{} {
	return bp.config
}

// SetDefaultModel sets the default model
func (bp *BaseProvider) SetDefaultModel(model string) {
	bp.defaultModel = model
}

// GetDefaultModel returns the default model
func (bp *BaseProvider) GetDefaultModel() string {
	return bp.defaultModel
}

// SetSupportedModels sets the supported models
func (bp *BaseProvider) SetSupportedModels(models []golem.Model) {
	bp.supportedModels = models
}

// GetSupportedModels returns the supported models
func (bp *BaseProvider) GetSupportedModels() []golem.Model {
	return bp.supportedModels
}

// IsModelSupported checks if a model is supported
func (bp *BaseProvider) IsModelSupported(modelID string) bool {
	for _, model := range bp.supportedModels {
		if model.ID == modelID {
			return true
		}
	}
	return false
}

type StreamingProvider interface {
	golem.LLMProvider
	SupportsStreaming() bool
}

type ProviderFactory interface {
	CreateProvider(providerType ProviderType, config map[string]interface{}) (golem.LLMProvider, error)
	GetSupportedProviders() []ProviderType
}

var Registry = make(map[string]golem.LLMProvider)

func RegisterProvider(name string, provider golem.LLMProvider) {
	Registry[name] = provider
}

// GetProvider gets an LLM provider by name
func GetProvider(name string) (golem.LLMProvider, bool) {
	provider, exists := Registry[name]
	return provider, exists
}

// ListProviders returns all registered provider names
func ListProviders() []string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	return names
}

type ProviderManager struct {
	providers       map[string]golem.LLMProvider
	defaultProvider string
}

// NewProviderManager creates a new provider manager
func NewProviderManager() *ProviderManager {
	return &ProviderManager{
		providers: make(map[string]golem.LLMProvider),
	}
}

// AddProvider adds a provider to the manager
func (pm *ProviderManager) AddProvider(name string, provider golem.LLMProvider) {
	pm.providers[name] = provider
}

// GetProvider gets a provider by name
func (pm *ProviderManager) GetProvider(name string) (golem.LLMProvider, error) {
	if provider, exists := pm.providers[name]; exists {
		return provider, nil
	}
	return nil, fmt.Errorf("provider %s not found", name)
}

// SetDefault sets the default provider
func (pm *ProviderManager) SetDefault(name string) error {
	if _, exists := pm.providers[name]; !exists {
		return fmt.Errorf("provider %s not found", name)
	}
	pm.defaultProvider = name
	return nil
}

// GetDefault gets the default provider
func (pm *ProviderManager) GetDefault() (golem.LLMProvider, error) {
	if pm.defaultProvider == "" {
		return nil, fmt.Errorf("no default provider set")
	}
	return pm.GetProvider(pm.defaultProvider)
}

// ListProviders returns all provider names
func (pm *ProviderManager) ListProviders() []string {
	names := make([]string, 0, len(pm.providers))
	for name := range pm.providers {
		names = append(names, name)
	}
	return names
}

// RemoveProvider removes a provider
func (pm *ProviderManager) RemoveProvider(name string) {
	delete(pm.providers, name)
	if pm.defaultProvider == name {
		pm.defaultProvider = ""
	}
}

// Clear removes all providers
func (pm *ProviderManager) Clear() {
	pm.providers = make(map[string]golem.LLMProvider)
	pm.defaultProvider = ""
}

// ValidateGenerationRequest validates a generation request
func ValidateGenerationRequest(req *golem.GenerationRequest) error {
	if req.Prompt == "" {
		return fmt.Errorf("prompt is required")
	}
	if req.Model == "" {
		return fmt.Errorf("model is required")
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = 1000
	}
	if req.Temperature < 0 || req.Temperature > 2 {
		return fmt.Errorf("temperature must be between 0 and 2")
	}
	return nil
}

// BuildPromptWithHistory builds a prompt with conversation history
func BuildPromptWithHistory(basePrompt string, history []golem.ConversationItem, maxHistoryTokens int) string {
	if len(history) == 0 {
		return basePrompt
	}

	// TODO: Implement a better way to handle history length and token limits
	historyText := ""
	for i := len(history) - min(len(history), 5); i < len(history); i++ {
		item := history[i]
		historyText += fmt.Sprintf("%s: %s\n", item.Role, item.Content)
	}

	if historyText != "" {
		return fmt.Sprintf("Previous conversation:\n%s\n\nCurrent request:\n%s", historyText, basePrompt)
	}

	return basePrompt
}

// EstimateTokenCount provides a rough token count estimation
func EstimateTokenCount(text string) int {
	// TODO: Implement a more accurate token counting algorithm
	return len(text) / 4
}

// SanitizePrompt sanitizes a prompt to remove potentially harmful content
func SanitizePrompt(prompt string) string {
	// TODO: Implement a more sophisticated sanitization logic
	// for example, removing potentially harmful keywords or phrases.
	return prompt
}

// FormatSystemMessage formats a system message
func FormatSystemMessage(role, instructions string, capabilities []string) string {
	msg := fmt.Sprintf("You are %s. %s", role, instructions)

	if len(capabilities) > 0 {
		msg += "\n\nYour capabilities include:"
		for _, cap := range capabilities {
			msg += fmt.Sprintf("\n- %s", cap)
		}
	}

	return msg
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
