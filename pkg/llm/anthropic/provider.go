// Package anthropic provides Anthropic LLM provider implementation for GoLEM.
package anthropic

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
	"github.com/sirupsen/logrus"
)

type Provider struct {
	client    *http.Client
	apiKey    string
	baseURL   string
	model     string
	maxTokens int
	logger    *logrus.Logger
}

type Config struct {
	APIKey    string `json:"api_key" mapstructure:"api_key"`
	BaseURL   string `json:"base_url" mapstructure:"base_url"`
	Model     string `json:"model" mapstructure:"model"`
	MaxTokens int    `json:"max_tokens" mapstructure:"max_tokens"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type CompletionRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
	Stream    bool      `json:"stream,omitempty"`
}

type CompletionResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model        string `json:"model"`
	StopReason   string `json:"stop_reason"`
	StopSequence string `json:"stop_sequence"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type StreamResponse struct {
	Type  string `json:"type"`
	Index int    `json:"index,omitempty"`
	Delta struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"delta,omitempty"`
}

// NewProvider creates a new Anthropic provider instance.
func NewProvider(config Config, logger *logrus.Logger) *Provider {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.anthropic.com/v1"
	}
	if config.Model == "" {
		config.Model = "claude-3-sonnet-20240229"
	}
	if config.MaxTokens == 0 {
		config.MaxTokens = 1024
	}

	return &Provider{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		apiKey:    config.APIKey,
		baseURL:   config.BaseURL,
		model:     config.Model,
		maxTokens: config.MaxTokens,
		logger:    logger,
	}
}

// GenerateResponse generates a response from the Anthropic model.
func (p *Provider) GenerateResponse(ctx context.Context, req *golem.LLMRequest) (*golem.LLMResponse, error) {
	messages := make([]Message, 0, len(req.Messages))
	for _, msg := range req.Messages {
		messages = append(messages, Message{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}

	completionReq := CompletionRequest{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		Messages:  messages,
		Stream:    false,
	}

	reqBody, err := json.Marshal(completionReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/messages", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var completionResp CompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&completionResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var content string
	if len(completionResp.Content) > 0 {
		content = completionResp.Content[0].Text
	}

	llmResp := &golem.LLMResponse{
		Content: content,
		Usage: golem.Usage{
			PromptTokens:     completionResp.Usage.InputTokens,
			CompletionTokens: completionResp.Usage.OutputTokens,
			TotalTokens:      completionResp.Usage.InputTokens + completionResp.Usage.OutputTokens,
		},
		FinishReason: completionResp.StopReason,
	}

	return llmResp, nil
}

// GenerateStreamResponse generates a streaming response from the Anthropic model.
func (p *Provider) GenerateStreamResponse(ctx context.Context, req *golem.LLMRequest, callback func(*golem.LLMStreamResponse) error) error {
	messages := make([]Message, 0, len(req.Messages))
	for _, msg := range req.Messages {
		messages = append(messages, Message{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}

	completionReq := CompletionRequest{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		Messages:  messages,
		Stream:    true,
	}

	reqBody, err := json.Marshal(completionReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/messages", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	reader := io.Reader(resp.Body)
	buf := make([]byte, 4096)
	var buffer strings.Builder

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			buffer.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read stream: %w", err)
		}

		content := buffer.String()
		lines := strings.Split(content, "\n")

		if len(lines) > 0 && !strings.HasSuffix(content, "\n") {
			buffer.Reset()
			buffer.WriteString(lines[len(lines)-1])
			lines = lines[:len(lines)-1]
		} else {
			buffer.Reset()
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || line == "data: [DONE]" {
				continue
			}

			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")

				var streamResp StreamResponse
				if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
					p.logger.WithError(err).Warn("Failed to parse stream response")
					continue
				}

				if streamResp.Type == "content_block_delta" {
					llmStreamResp := &golem.LLMStreamResponse{
						Content: streamResp.Delta.Text,
						Done:    false,
					}

					if err := callback(llmStreamResp); err != nil {
						return fmt.Errorf("callback error: %w", err)
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	finalResp := &golem.LLMStreamResponse{
		Content: "",
		Done:    true,
	}

	return callback(finalResp)
}

// CallTool calls a tool with the given parameters.
func (p *Provider) CallTool(ctx context.Context, toolCall *golem.ToolCall) (*golem.ToolResult, error) {
	// TODO: Implement tool calling logic for Anthropic.
	parametersJSON, _ := json.Marshal(toolCall.Parameters)
	return &golem.ToolResult{
		ToolCallID: toolCall.ID,
		Content:    fmt.Sprintf("Tool %s executed with parameters: %s", toolCall.Name, string(parametersJSON)),
		Error:      nil,
	}, nil
}

// SupportsStreaming returns true if the provider supports streaming responses.
func (p *Provider) SupportsStreaming() bool {
	return true
}

// SupportsToolCalling returns true if the provider supports tool calling.
func (p *Provider) SupportsToolCalling() bool {
	// TODO: Implement a check for tool calling support.
	// For now, we assume it does not support tool calling.
	return false
}

// GetModelInfo returns information about the current model.
func (p *Provider) GetModelInfo() golem.ModelInfo {
	return golem.ModelInfo{
		Name:         p.model,
		Provider:     "anthropic",
		MaxTokens:    p.maxTokens,
		SupportsChat: true,
	}
}
