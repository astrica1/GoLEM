// Package openai provides OpenAI LLM provider implementation for GoLEM.
package openai

import (
	"context"
	"fmt"
	"strings"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/astrica1/GoLEM/pkg/llm"
	"github.com/sashabaranov/go-openai"
	"github.com/sirupsen/logrus"
)

type Provider struct {
	*llm.BaseProvider
	client  *openai.Client
	logger  *logrus.Logger
	apiKey  string
	baseURL string
}

type Config struct {
	APIKey  string `json:"api_key" yaml:"api_key"`
	BaseURL string `json:"base_url" yaml:"base_url"`
	OrgID   string `json:"org_id" yaml:"org_id"`
}

// NewProvider creates a new OpenAI provider
func NewProvider(apiKey string, config ...Config) golem.LLMProvider {
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	if apiKey == "" {
		apiKey = cfg.APIKey
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	clientConfig := openai.DefaultConfig(apiKey)
	if cfg.BaseURL != "" {
		clientConfig.BaseURL = cfg.BaseURL
	}
	if cfg.OrgID != "" {
		clientConfig.OrgID = cfg.OrgID
	}

	client := openai.NewClientWithConfig(clientConfig)

	provider := &Provider{
		BaseProvider: llm.NewBaseProvider("openai", llm.ProviderTypeOpenAI),
		client:       client,
		logger:       logger,
		apiKey:       apiKey,
		baseURL:      baseURL,
	}

	provider.SetDefaultModel("gpt-3.5-turbo")

	provider.SetSupportedModels(getOpenAIModels())

	provider.SetConfig(map[string]interface{}{
		"api_key":  apiKey,
		"base_url": baseURL,
		"org_id":   cfg.OrgID,
	})

	logger.WithFields(logrus.Fields{
		"provider": "openai",
		"base_url": baseURL,
	}).Info("OpenAI provider initialized")

	return provider
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
	}).Debug("Generating OpenAI response")

	messages := []openai.ChatCompletionMessage{}
	if req.SystemMsg != "" {
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleSystem,
			Content: req.SystemMsg,
		})
	}

	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: req.Prompt,
	})

	chatRequest := openai.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
		TopP:        1,
		N:           1,
		Stop:        nil,
	}

	if len(req.Tools) > 0 {
		functions := make([]openai.FunctionDefinition, len(req.Tools))
		for i, tool := range req.Tools {
			functions[i] = openai.FunctionDefinition{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  convertToolSchemaToOpenAI(tool.Parameters),
			}
		}
		chatRequest.Functions = functions
		chatRequest.FunctionCall = "auto"
	}

	response, err := p.client.CreateChatCompletion(ctx, chatRequest)
	if err != nil {
		p.logger.WithError(err).Error("OpenAI API call failed")
		return nil, fmt.Errorf("openai api error: %w", err)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no response choices returned from openai")
	}

	choice := response.Choices[0]

	result := &golem.GenerationResponse{
		Text:         choice.Message.Content,
		TokensUsed:   response.Usage.TotalTokens,
		Model:        response.Model,
		FinishReason: string(choice.FinishReason),
		Metadata: map[string]interface{}{
			"prompt_tokens":     response.Usage.PromptTokens,
			"completion_tokens": response.Usage.CompletionTokens,
			"total_tokens":      response.Usage.TotalTokens,
		},
	}

	if choice.Message.FunctionCall != nil {
		toolCall := golem.ToolCall{
			ID:   choice.Message.FunctionCall.Name,
			Name: choice.Message.FunctionCall.Name,
		}

		if choice.Message.FunctionCall.Arguments != "" {
			// TODO: Parse JSON arguments into a map
			toolCall.Parameters = map[string]interface{}{
				"arguments": choice.Message.FunctionCall.Arguments,
			}
		}

		result.ToolCalls = []golem.ToolCall{toolCall}
	}

	p.logger.WithFields(logrus.Fields{
		"tokens_used":   result.TokensUsed,
		"finish_reason": result.FinishReason,
		"tool_calls":    len(result.ToolCalls),
	}).Debug("OpenAI response generated successfully")

	return result, nil
}

// GenerateStream generates a streaming response
func (p *Provider) GenerateStream(ctx context.Context, req *golem.GenerationRequest, callback golem.StreamCallback) error {
	if err := llm.ValidateGenerationRequest(req); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	p.logger.WithField("model", req.Model).Debug("Starting OpenAI streaming response")
	messages := []openai.ChatCompletionMessage{}
	if req.SystemMsg != "" {
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleSystem,
			Content: req.SystemMsg,
		})
	}

	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: req.Prompt,
	})

	chatRequest := openai.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
		Stream:      true,
	}

	stream, err := p.client.CreateChatCompletionStream(ctx, chatRequest)
	if err != nil {
		p.logger.WithError(err).Error("Failed to create OpenAI stream")
		return fmt.Errorf("failed to create stream: %w", err)
	}
	defer stream.Close()

	var fullText strings.Builder
	for {
		response, err := stream.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			p.logger.WithError(err).Error("Error receiving from OpenAI stream")
			return fmt.Errorf("stream error: %w", err)
		}

		if len(response.Choices) > 0 {
			choice := response.Choices[0]
			delta := choice.Delta.Content
			fullText.WriteString(delta)
			chunk := &golem.StreamChunk{
				Text:       fullText.String(),
				Delta:      delta,
				IsComplete: choice.FinishReason != "",
				Metadata: map[string]interface{}{
					"finish_reason": string(choice.FinishReason),
					"model":         response.Model,
				},
			}

			if err := callback(chunk); err != nil {
				p.logger.WithError(err).Warn("Stream callback error")
				return err
			}

			if chunk.IsComplete {
				break
			}
		}
	}

	p.logger.Debug("OpenAI streaming completed")
	return nil
}

// GetModels returns the list of available models
func (p *Provider) GetModels(ctx context.Context) ([]golem.Model, error) {
	// TODO: Implement OpenAI API call to fetch models if needed
	return p.GetSupportedModels(), nil
}

// GetTokenCount estimates the token count for the given text
func (p *Provider) GetTokenCount(text string, model string) (int, error) {
	// TODO: Implement OpenAI API call to estimate token count if needed
	return llm.EstimateTokenCount(text), nil
}

// ValidateConfig validates the provider configuration
func (p *Provider) ValidateConfig(config map[string]interface{}) error {
	if p.apiKey == "" {
		return fmt.Errorf("api_key is required for OpenAI provider")
	}

	if modelInterface, exists := config["model"]; exists {
		if model, ok := modelInterface.(string); ok {
			if !p.IsModelSupported(model) {
				return fmt.Errorf("model %s is not supported by OpenAI provider", model)
			}
		}
	}

	return nil
}

// SupportsStreaming returns true if the provider supports streaming
func (p *Provider) SupportsStreaming() bool {
	return true
}

// convertToolSchemaToOpenAI converts GoLEM tool schema to OpenAI function parameters format
func convertToolSchemaToOpenAI(schema golem.ToolSchema) interface{} {
	// TODO: Implement conversion logic for GoLEM tool schema to OpenAI function parameters
	result := map[string]interface{}{
		"type":       schema.Type,
		"properties": make(map[string]interface{}),
	}

	if len(schema.Required) > 0 {
		result["required"] = schema.Required
	}

	for name, prop := range schema.Properties {
		propMap := map[string]interface{}{
			"type":        prop.Type,
			"description": prop.Description,
		}

		if len(prop.Enum) > 0 {
			propMap["enum"] = prop.Enum
		}

		if prop.Items != nil {
			propMap["items"] = prop.Items
		}

		result["properties"].(map[string]interface{})[name] = propMap
	}

	return result
}

// getOpenAIModels returns the list of supported OpenAI models
func getOpenAIModels() []golem.Model {
	return []golem.Model{
		{
			ID:           "gpt-4",
			Name:         "GPT-4",
			Provider:     "openai",
			Capabilities: []string{"chat", "function_calling"},
			MaxTokens:    8192,
			CostPer1K:    0.03,
		},
		{
			ID:           "gpt-4-turbo-preview",
			Name:         "GPT-4 Turbo Preview",
			Provider:     "openai",
			Capabilities: []string{"chat", "function_calling", "json_mode"},
			MaxTokens:    128000,
			CostPer1K:    0.01,
		},
		{
			ID:           "gpt-4-vision-preview",
			Name:         "GPT-4 Vision Preview",
			Provider:     "openai",
			Capabilities: []string{"chat", "vision", "function_calling"},
			MaxTokens:    128000,
			CostPer1K:    0.01,
		},
		{
			ID:           "gpt-3.5-turbo",
			Name:         "GPT-3.5 Turbo",
			Provider:     "openai",
			Capabilities: []string{"chat", "function_calling"},
			MaxTokens:    4096,
			CostPer1K:    0.001,
		},
		{
			ID:           "gpt-3.5-turbo-16k",
			Name:         "GPT-3.5 Turbo 16K",
			Provider:     "openai",
			Capabilities: []string{"chat", "function_calling"},
			MaxTokens:    16384,
			CostPer1K:    0.003,
		},
		{
			ID:           "text-davinci-003",
			Name:         "Text Davinci 003",
			Provider:     "openai",
			Capabilities: []string{"completion"},
			MaxTokens:    4096,
			CostPer1K:    0.02,
		},
		{
			ID:           "text-embedding-ada-002",
			Name:         "Text Embedding Ada 002",
			Provider:     "openai",
			Capabilities: []string{"embeddings"},
			MaxTokens:    8191,
			CostPer1K:    0.0001,
		},
	}
}
