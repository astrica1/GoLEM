// Package ollama provides Ollama LLM provider implementation for GoLEM.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/astrica1/GoLEM/pkg/llm"
	"github.com/sirupsen/logrus"
)

type Provider struct {
	*llm.BaseProvider
	client  *http.Client
	logger  *logrus.Logger
	baseURL string
}

type Config struct {
	BaseURL string `json:"base_url" yaml:"base_url"`
}

// NewProvider creates a new Ollama provider
func NewProvider(config ...Config) golem.LLMProvider {
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	provider := &Provider{
		BaseProvider: llm.NewBaseProvider("ollama", llm.ProviderTypeOllama),
		client:       &http.Client{},
		logger:       logger,
		baseURL:      baseURL,
	}

	// this will be updated when we fetch available models!
	provider.SetDefaultModel("llama2")
	provider.SetConfig(map[string]interface{}{
		"base_url": baseURL,
	})

	logger.WithFields(logrus.Fields{
		"provider": "ollama",
		"base_url": baseURL,
	}).Info("Ollama provider initialized")

	return provider
}

type OllamaRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	System  string                 `json:"system,omitempty"`
	Stream  bool                   `json:"stream"`
	Options map[string]interface{} `json:"options,omitempty"`
}

type OllamaResponse struct {
	Model              string `json:"model"`
	CreatedAt          string `json:"created_at"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	Context            []int  `json:"context,omitempty"`
	TotalDuration      int64  `json:"total_duration,omitempty"`
	LoadDuration       int64  `json:"load_duration,omitempty"`
	PromptEvalCount    int    `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64  `json:"prompt_eval_duration,omitempty"`
	EvalCount          int    `json:"eval_count,omitempty"`
	EvalDuration       int64  `json:"eval_duration,omitempty"`
}

type OllamaModelResponse struct {
	Models []OllamaModel `json:"models"`
}

type OllamaModel struct {
	Name       string                 `json:"name"`
	ModifiedAt string                 `json:"modified_at"`
	Size       int64                  `json:"size"`
	Digest     string                 `json:"digest"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// GenerateResponse generates a response for the given prompt
func (p *Provider) GenerateResponse(ctx context.Context, req *golem.GenerationRequest) (*golem.GenerationResponse, error) {
	if err := llm.ValidateGenerationRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	p.logger.WithFields(logrus.Fields{
		"model":       req.Model,
		"temperature": req.Temperature,
		"max_tokens":  req.MaxTokens,
	}).Debug("Generating Ollama response")

	options := map[string]interface{}{}
	if req.Temperature > 0 {
		options["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		options["num_predict"] = req.MaxTokens
	}

	ollamaReq := OllamaRequest{
		Model:   req.Model,
		Prompt:  req.Prompt,
		System:  req.SystemMsg,
		Stream:  false,
		Options: options,
	}

	response, err := p.makeRequest(ctx, ollamaReq)
	if err != nil {
		return nil, err
	}

	result := &golem.GenerationResponse{
		Text:         response.Response,
		Model:        response.Model,
		FinishReason: "stop",
		TokensUsed:   response.PromptEvalCount + response.EvalCount,
		Metadata: map[string]interface{}{
			"total_duration":       response.TotalDuration,
			"load_duration":        response.LoadDuration,
			"prompt_eval_count":    response.PromptEvalCount,
			"prompt_eval_duration": response.PromptEvalDuration,
			"eval_count":           response.EvalCount,
			"eval_duration":        response.EvalDuration,
		},
	}

	p.logger.WithFields(logrus.Fields{
		"tokens_used": result.TokensUsed,
		"duration":    response.TotalDuration,
	}).Debug("Ollama response generated successfully")

	return result, nil
}

// GenerateStream generates a streaming response
func (p *Provider) GenerateStream(ctx context.Context, req *golem.GenerationRequest, callback golem.StreamCallback) error {
	if err := llm.ValidateGenerationRequest(req); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	p.logger.WithField("model", req.Model).Debug("Starting Ollama streaming response")
	options := map[string]interface{}{}
	if req.Temperature > 0 {
		options["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		options["num_predict"] = req.MaxTokens
	}

	ollamaReq := OllamaRequest{
		Model:   req.Model,
		Prompt:  req.Prompt,
		System:  req.SystemMsg,
		Stream:  true,
		Options: options,
	}

	err := p.makeStreamingRequest(ctx, ollamaReq, callback)
	if err != nil {
		return err
	}

	p.logger.Debug("Ollama streaming completed")
	return nil
}

// GetModels returns the list of available models
func (p *Provider) GetModels(ctx context.Context) ([]golem.Model, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/api/tags", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama models api error (status %d): %s", resp.StatusCode, string(body))
	}

	var modelsResp OllamaModelResponse
	if err := json.NewDecoder(resp.Body).Decode(&modelsResp); err != nil {
		return nil, fmt.Errorf("failed to decode models response: %w", err)
	}

	models := make([]golem.Model, len(modelsResp.Models))
	for i, model := range modelsResp.Models {
		models[i] = golem.Model{
			ID:           model.Name,
			Name:         model.Name,
			Provider:     "ollama",
			Capabilities: []string{"chat", "completion"},
			MaxTokens:    4096,
			CostPer1K:    0.0,
		}
	}

	return models, nil
}

// GetTokenCount estimates the token count for the given text
func (p *Provider) GetTokenCount(text string, model string) (int, error) {
	return llm.EstimateTokenCount(text), nil
}

// ValidateConfig validates the provider configuration
func (p *Provider) ValidateConfig(config map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.GetModels(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to Ollama service: %w", err)
	}

	return nil
}

// SupportsStreaming returns true if the provider supports streaming
func (p *Provider) SupportsStreaming() bool {
	return true
}

// makeRequest makes a non-streaming API request to Ollama
func (p *Provider) makeRequest(ctx context.Context, req OllamaRequest) (*OllamaResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.logger.WithError(err).Error("Ollama API request failed")
		return nil, fmt.Errorf("ollama api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama api error (status %d): %s", resp.StatusCode, string(body))
	}

	var fullResponse OllamaResponse
	var fullText strings.Builder

	decoder := json.NewDecoder(resp.Body)
	for {
		var response OllamaResponse
		if err := decoder.Decode(&response); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		fullText.WriteString(response.Response)
		fullResponse = response

		if response.Done {
			break
		}
	}

	fullResponse.Response = fullText.String()
	return &fullResponse, nil
}

// makeStreamingRequest makes a streaming API request to Ollama
func (p *Provider) makeStreamingRequest(ctx context.Context, req OllamaRequest, callback golem.StreamCallback) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ollama streaming request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama streaming api error (status %d): %s", resp.StatusCode, string(body))
	}

	var fullText strings.Builder
	decoder := json.NewDecoder(resp.Body)

	for {
		var response OllamaResponse
		if err := decoder.Decode(&response); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to decode streaming response: %w", err)
		}

		fullText.WriteString(response.Response)

		chunk := &golem.StreamChunk{
			Text:       fullText.String(),
			Delta:      response.Response,
			IsComplete: response.Done,
			Metadata: map[string]interface{}{
				"model":         response.Model,
				"created_at":    response.CreatedAt,
				"eval_count":    response.EvalCount,
				"eval_duration": response.EvalDuration,
			},
		}

		if err := callback(chunk); err != nil {
			return err
		}

		if response.Done {
			break
		}
	}

	return nil
}

// RefreshModels refreshes the list of available models
func (p *Provider) RefreshModels(ctx context.Context) error {
	models, err := p.GetModels(ctx)
	if err != nil {
		return err
	}

	p.SetSupportedModels(models)

	if p.GetDefaultModel() == "llama2" && len(models) > 0 {
		p.SetDefaultModel(models[0].ID)
	}

	p.logger.WithField("model_count", len(models)).Info("Ollama models refreshed")
	return nil
}

// PullModel pulls a model from the Ollama registry
func (p *Provider) PullModel(ctx context.Context, modelName string) error {
	pullReq := map[string]string{
		"name": modelName,
	}

	jsonData, err := json.Marshal(pullReq)
	if err != nil {
		return fmt.Errorf("failed to marshal pull request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/pull", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to pull model: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama pull api error (status %d): %s", resp.StatusCode, string(body))
	}

	p.logger.WithField("model", modelName).Info("Model pull initiated")
	return nil
}

// GetInfo gets information about the Ollama service
func (p *Provider) GetInfo(ctx context.Context) (map[string]interface{}, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/api/version", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama info api error (status %d): %s", resp.StatusCode, string(body))
	}

	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode info response: %w", err)
	}

	return info, nil
}
