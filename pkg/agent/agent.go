// Package agent provides agent implementation for the Go Language Execution Model.
package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/astrica1/GoLEM/pkg/memory"
	"github.com/astrica1/GoLEM/pkg/tools"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type agent struct {
	id           string
	name         string
	role         string
	config       Config
	llmProvider  golem.LLMProvider
	memory       golem.Memory
	tools        map[string]golem.Tool
	capabilities []golem.Capability
	logger       *logrus.Logger
	healthy      bool
	mu           sync.RWMutex
	createdAt    time.Time
}

type Config struct {
	Name         string                 `json:"name" yaml:"name"`
	Role         string                 `json:"role" yaml:"role"`
	LLMProvider  golem.LLMProvider      `json:"-" yaml:"-"`
	Model        string                 `json:"model" yaml:"model"`
	Temperature  float32                `json:"temperature" yaml:"temperature"`
	MaxTokens    int                    `json:"max_tokens" yaml:"max_tokens"`
	SystemPrompt string                 `json:"system_prompt" yaml:"system_prompt"`
	Tools        []string               `json:"tools" yaml:"tools"`
	Memory       golem.MemoryConfig     `json:"memory" yaml:"memory"`
	CustomConfig map[string]interface{} `json:"custom_config" yaml:"custom_config"`
}

// NewAgent creates a new agent with the given configuration
func NewAgent(name string, config Config) golem.Agent {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	if config.Name == "" {
		config.Name = name
	}
	if config.Temperature == 0 {
		config.Temperature = 0.7
	}
	if config.MaxTokens == 0 {
		config.MaxTokens = 1000
	}
	if config.CustomConfig == nil {
		config.CustomConfig = make(map[string]interface{})
	}

	agent := &agent{
		id:           uuid.New().String(),
		name:         config.Name,
		role:         config.Role,
		config:       config,
		llmProvider:  config.LLMProvider,
		tools:        make(map[string]golem.Tool),
		capabilities: make([]golem.Capability, 0),
		logger:       logger,
		healthy:      true,
		createdAt:    time.Now(),
	}

	if config.Memory.Backend == "" {
		config.Memory.Backend = "memory"
	}
	agent.memory = memory.NewMemory(config.Memory)

	agent.loadTools(config.Tools)
	agent.buildCapabilities()
	logger.WithFields(logrus.Fields{
		"agent_id":   agent.id,
		"agent_name": agent.name,
		"agent_role": agent.role,
		"model":      config.Model,
		"tools":      len(agent.tools),
	}).Info("Agent created")

	return agent
}

// ID returns the unique identifier of the agent
func (a *agent) ID() string {
	return a.id
}

// Name returns the human-readable name of the agent
func (a *agent) Name() string {
	return a.name
}

// Role returns the role/purpose of the agent
func (a *agent) Role() string {
	return a.role
}

// Execute runs a task and returns the result
func (a *agent) Execute(ctx context.Context, task golem.Task) (*golem.TaskResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.healthy {
		return nil, fmt.Errorf("agent %s is not healthy", a.id)
	}

	start := time.Now()

	a.logger.WithFields(logrus.Fields{
		"agent_id":    a.id,
		"task_id":     task.ID(),
		"task_name":   task.Name(),
		"description": task.Description(),
	}).Info("Starting task execution")

	result := golem.NewTaskResult(task.ID(), a.id)

	history, err := a.memory.GetConversationHistory(ctx, a.id, 10)
	if err != nil {
		a.logger.WithError(err).Warn("Failed to get conversation history")
		history = []golem.ConversationItem{}
	}

	prompt, err := a.preparePrompt(task, history)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to prepare prompt: %v", err)
		result.Duration = time.Since(start)
		return result, err
	}

	toolDefinitions := make([]golem.ToolDefinition, 0, len(a.tools))
	for _, tool := range a.tools {
		toolDefinitions = append(toolDefinitions, golem.ToolDefinition{
			Name:        tool.Name(),
			Description: tool.Description(),
			Parameters:  tool.GetSchema(),
		})
	}

	request := &golem.GenerationRequest{
		Prompt:      prompt,
		Model:       a.config.Model,
		Temperature: a.config.Temperature,
		MaxTokens:   a.config.MaxTokens,
		SystemMsg:   a.buildSystemMessage(),
		Tools:       toolDefinitions,
		Context:     task.GetInput().Context,
	}

	response, err := a.llmProvider.GenerateResponse(ctx, request)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("LLM generation failed: %v", err)
		result.Duration = time.Since(start)

		a.logger.WithError(err).WithField("task_id", task.ID()).Error("LLM generation failed")
		return result, err
	}

	if len(response.ToolCalls) > 0 {
		toolResults, err := a.executeToolCalls(ctx, response.ToolCalls)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Tool execution failed: %v", err)
			result.Duration = time.Since(start)
			return result, err
		}

		finalResponse, err := a.generateWithToolResults(ctx, request, response, toolResults)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Final generation with tool results failed: %v", err)
			result.Duration = time.Since(start)
			return result, err
		}
		response = finalResponse
	}

	userMessage := golem.ConversationItem{
		ID:        golem.NewUUID(),
		AgentID:   a.id,
		Role:      "user",
		Content:   prompt,
		Metadata:  task.GetInput().Context,
		Timestamp: start,
	}

	assistantMessage := golem.ConversationItem{
		ID:      golem.NewUUID(),
		AgentID: a.id,
		Role:    "assistant",
		Content: response.Text,
		Metadata: map[string]interface{}{
			"model":         response.Model,
			"tokens_used":   response.TokensUsed,
			"finish_reason": response.FinishReason,
		},
		Timestamp: time.Now(),
	}

	if err := a.memory.AddToConversation(ctx, a.id, userMessage); err != nil {
		a.logger.WithError(err).Warn("Failed to save user message to conversation history")
	}

	if err := a.memory.AddToConversation(ctx, a.id, assistantMessage); err != nil {
		a.logger.WithError(err).Warn("Failed to save assistant message to conversation history")
	}

	result.Output = response.Text
	result.TokensUsed = response.TokensUsed
	result.Success = true
	result.Duration = time.Since(start)
	result.Metadata = map[string]interface{}{
		"model":           response.Model,
		"finish_reason":   response.FinishReason,
		"tool_calls_used": len(response.ToolCalls),
	}

	a.logger.WithFields(logrus.Fields{
		"agent_id":    a.id,
		"task_id":     task.ID(),
		"duration":    result.Duration,
		"tokens_used": result.TokensUsed,
	}).Info("Task execution completed")

	return result, nil
}

// Configure updates the agent's configuration
func (a *agent) Configure(config golem.AgentConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if config.Name != "" {
		a.name = config.Name
	}
	if config.Role != "" {
		a.role = config.Role
	}
	if config.Temperature != 0 {
		a.config.Temperature = config.Temperature
	}
	if config.MaxTokens != 0 {
		a.config.MaxTokens = config.MaxTokens
	}

	if len(config.Tools) > 0 {
		a.tools = make(map[string]golem.Tool)
		a.loadTools(config.Tools)
		a.buildCapabilities()
	}

	a.logger.WithField("agent_id", a.id).Info("Agent configuration updated")
	return nil
}

// GetCapabilities returns the agent's available capabilities
func (a *agent) GetCapabilities() []golem.Capability {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.capabilities
}

// GetMemory returns the agent's memory interface
func (a *agent) GetMemory() golem.Memory {
	return a.memory
}

// IsHealthy checks if the agent is ready to execute tasks
func (a *agent) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.healthy {
		return false
	}

	if a.llmProvider != nil {
		err := a.llmProvider.ValidateConfig(map[string]interface{}{
			"model": a.config.Model,
		})
		if err != nil {
			a.logger.WithError(err).Warn("LLM provider validation failed")
			return false
		}
	}

	return true
}

// preparePrompt prepares the prompt for the LLM
func (a *agent) preparePrompt(task golem.Task, history []golem.ConversationItem) (string, error) {
	prompt := fmt.Sprintf("Task: %s\n\nDescription: %s\n\n", task.Name(), task.Description())

	input := task.GetInput()
	if input.Text != "" {
		prompt += fmt.Sprintf("Input: %s\n\n", input.Text)
	}

	if len(input.Parameters) > 0 {
		prompt += "Parameters:\n"
		for key, value := range input.Parameters {
			prompt += fmt.Sprintf("- %s: %v\n", key, value)
		}
		prompt += "\n"
	}

	if len(history) > 0 {
		prompt += "Recent conversation context:\n"
		for i := max(0, len(history)-3); i < len(history); i++ {
			item := history[i]
			prompt += fmt.Sprintf("%s: %s\n", item.Role, item.Content[:min(200, len(item.Content))])
		}
		prompt += "\n"
	}

	prompt += "Please provide a comprehensive response to complete this task."

	return prompt, nil
}

// buildSystemMessage builds the system message for the LLM
func (a *agent) buildSystemMessage() string {
	systemMsg := fmt.Sprintf("You are %s. %s", a.name, a.role)

	if a.config.SystemPrompt != "" {
		systemMsg += "\n\n" + a.config.SystemPrompt
	}

	if len(a.tools) > 0 {
		systemMsg += "\n\nYou have access to the following tools. Use them when appropriate to help complete tasks:"
		for _, tool := range a.tools {
			systemMsg += fmt.Sprintf("\n- %s: %s", tool.Name(), tool.Description())
		}
	}

	return systemMsg
}

// loadTools loads the specified tools for the agent
func (a *agent) loadTools(toolNames []string) {
	for _, toolName := range toolNames {
		tool, err := tools.GetTool(toolName)
		if err != nil {
			a.logger.WithError(err).WithField("tool_name", toolName).Warn("Failed to load tool")
			continue
		}

		a.tools[toolName] = tool
	}
}

// buildCapabilities builds the agent's capabilities based on available tools
func (a *agent) buildCapabilities() {
	capabilities := []golem.Capability{
		{
			Name:        "text_generation",
			Description: "Generate text responses using language model capabilities",
			Required:    true,
		},
		{
			Name:        "conversation",
			Description: "Maintain conversation context and history",
			Required:    true,
		},
	}

	toolNames := make([]string, 0, len(a.tools))
	for toolName := range a.tools {
		toolNames = append(toolNames, toolName)
	}

	if len(toolNames) > 0 {
		capabilities = append(capabilities, golem.Capability{
			Name:        "tool_usage",
			Description: "Use various tools to perform specific tasks",
			Tools:       toolNames,
			Required:    false,
		})
	}

	a.capabilities = capabilities
}

// executeToolCalls executes the tool calls from the LLM response
func (a *agent) executeToolCalls(ctx context.Context, toolCalls []golem.ToolCall) ([]ToolCallResult, error) {
	results := make([]ToolCallResult, len(toolCalls))

	for i, toolCall := range toolCalls {
		tool, exists := a.tools[toolCall.Name]
		if !exists {
			results[i] = ToolCallResult{
				ID:    toolCall.ID,
				Name:  toolCall.Name,
				Error: fmt.Sprintf("tool '%s' not found", toolCall.Name),
			}
			continue
		}

		if err := tool.ValidateParams(toolCall.Parameters); err != nil {
			results[i] = ToolCallResult{
				ID:    toolCall.ID,
				Name:  toolCall.Name,
				Error: fmt.Sprintf("invalid parameters: %v", err),
			}
			continue
		}

		result, err := tool.Execute(ctx, toolCall.Parameters)
		if err != nil {
			results[i] = ToolCallResult{
				ID:    toolCall.ID,
				Name:  toolCall.Name,
				Error: err.Error(),
			}
			continue
		}

		results[i] = ToolCallResult{
			ID:     toolCall.ID,
			Name:   toolCall.Name,
			Result: result,
		}

		a.logger.WithFields(logrus.Fields{
			"agent_id":  a.id,
			"tool_name": toolCall.Name,
			"tool_id":   toolCall.ID,
		}).Debug("Tool executed successfully")
	}

	return results, nil
}

// generateWithToolResults generates a final response incorporating tool results
func (a *agent) generateWithToolResults(ctx context.Context, originalRequest *golem.GenerationRequest, originalResponse *golem.GenerationResponse, toolResults []ToolCallResult) (*golem.GenerationResponse, error) {
	prompt := originalRequest.Prompt + "\n\nPrevious response:\n" + originalResponse.Text

	prompt += "\n\nTool execution results:"
	for _, result := range toolResults {
		if result.Error != "" {
			prompt += fmt.Sprintf("\n- %s (ID: %s): Error - %s", result.Name, result.ID, result.Error)
		} else {
			prompt += fmt.Sprintf("\n- %s (ID: %s): %v", result.Name, result.ID, result.Result)
		}
	}

	prompt += "\n\nPlease provide a final comprehensive response based on the original task and the tool results."

	finalRequest := &golem.GenerationRequest{
		Prompt:      prompt,
		Model:       originalRequest.Model,
		Temperature: originalRequest.Temperature,
		MaxTokens:   originalRequest.MaxTokens,
		SystemMsg:   originalRequest.SystemMsg,
		Context:     originalRequest.Context,
	}

	return a.llmProvider.GenerateResponse(ctx, finalRequest)
}

type ToolCallResult struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
