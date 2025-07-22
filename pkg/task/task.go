// Package task provides task implementation for the Go Language Execution Model.
package task

import (
	"fmt"
	"sync"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/google/uuid"
)

type task struct {
	id           string
	name         string
	description  string
	input        golem.TaskInput
	config       golem.TaskConfig
	dependencies []string
	result       *golem.TaskResult
	status       golem.TaskStatus
	createdAt    time.Time
	updatedAt    time.Time
	mu           sync.RWMutex
}

type Config struct {
	Name          string                 `json:"name" yaml:"name"`
	Description   string                 `json:"description" yaml:"description"`
	AssignedAgent string                 `json:"assigned_agent" yaml:"assigned_agent"`
	Priority      int                    `json:"priority" yaml:"priority"`
	Timeout       time.Duration          `json:"timeout" yaml:"timeout"`
	RetryCount    int                    `json:"retry_count" yaml:"retry_count"`
	RequiredTools []string               `json:"required_tools" yaml:"required_tools"`
	Dependencies  []string               `json:"dependencies" yaml:"dependencies"`
	Input         golem.TaskInput        `json:"input" yaml:"input"`
	CustomConfig  map[string]interface{} `json:"custom_config" yaml:"custom_config"`
}

// NewTask creates a new task with the given configuration
func NewTask(name string, config Config) golem.Task {
	taskConfig := golem.TaskConfig{
		Priority:      config.Priority,
		Timeout:       config.Timeout,
		RetryCount:    config.RetryCount,
		RequiredTools: config.RequiredTools,
		CustomConfig:  config.CustomConfig,
	}

	if taskConfig.CustomConfig == nil {
		taskConfig.CustomConfig = make(map[string]interface{})
	}

	if config.AssignedAgent != "" {
		taskConfig.CustomConfig["agent_id"] = config.AssignedAgent
	}

	if taskConfig.Timeout == 0 {
		taskConfig.Timeout = 5 * time.Minute
	}
	if taskConfig.RetryCount == 0 {
		taskConfig.RetryCount = 3
	}

	return &task{
		id:           uuid.New().String(),
		name:         config.Name,
		description:  config.Description,
		input:        config.Input,
		config:       taskConfig,
		dependencies: config.Dependencies,
		status:       golem.TaskStatusPending,
		createdAt:    time.Now(),
		updatedAt:    time.Now(),
	}
}

// ID returns the unique identifier of the task
func (t *task) ID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.id
}

// Name returns the human-readable name of the task
func (t *task) Name() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.name
}

// Description returns the task description
func (t *task) Description() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.description
}

// GetInput returns the task input data
func (t *task) GetInput() golem.TaskInput {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.input
}

// GetConfig returns the task configuration
func (t *task) GetConfig() golem.TaskConfig {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.config
}

// GetDependencies returns the list of task dependencies
func (t *task) GetDependencies() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	deps := make([]string, len(t.dependencies))
	copy(deps, t.dependencies)
	return deps
}

// SetResult sets the task execution result
func (t *task) SetResult(result *golem.TaskResult) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.result = result
	t.updatedAt = time.Now()
}

// GetResult returns the task execution result
func (t *task) GetResult() *golem.TaskResult {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.result
}

// GetStatus returns the current task status
func (t *task) GetStatus() golem.TaskStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

// SetStatus updates the task status
func (t *task) SetStatus(status golem.TaskStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.status = status
	t.updatedAt = time.Now()
}

type Builder struct {
	config Config
}

// NewBuilder creates a new task builder
func NewBuilder(name string) *Builder {
	return &Builder{
		config: Config{
			Name:         name,
			CustomConfig: make(map[string]interface{}),
			Input: golem.TaskInput{
				Parameters: make(map[string]interface{}),
				Context:    make(map[string]interface{}),
			},
		},
	}
}

// WithDescription sets the task description
func (b *Builder) WithDescription(description string) *Builder {
	b.config.Description = description
	return b
}

// WithAssignedAgent sets the assigned agent
func (b *Builder) WithAssignedAgent(agentID string) *Builder {
	b.config.AssignedAgent = agentID
	return b
}

// WithPriority sets the task priority
func (b *Builder) WithPriority(priority int) *Builder {
	b.config.Priority = priority
	return b
}

// WithTimeout sets the task timeout
func (b *Builder) WithTimeout(timeout time.Duration) *Builder {
	b.config.Timeout = timeout
	return b
}

// WithRetryCount sets the retry count
func (b *Builder) WithRetryCount(count int) *Builder {
	b.config.RetryCount = count
	return b
}

// WithRequiredTools sets the required tools
func (b *Builder) WithRequiredTools(tools []string) *Builder {
	b.config.RequiredTools = tools
	return b
}

// WithDependencies sets the task dependencies
func (b *Builder) WithDependencies(dependencies []string) *Builder {
	b.config.Dependencies = dependencies
	return b
}

// WithInputText sets the input text
func (b *Builder) WithInputText(text string) *Builder {
	b.config.Input.Text = text
	return b
}

// WithInputParameter adds an input parameter
func (b *Builder) WithInputParameter(key string, value interface{}) *Builder {
	if b.config.Input.Parameters == nil {
		b.config.Input.Parameters = make(map[string]interface{})
	}
	b.config.Input.Parameters[key] = value
	return b
}

// WithInputContext adds input context
func (b *Builder) WithInputContext(key string, value interface{}) *Builder {
	if b.config.Input.Context == nil {
		b.config.Input.Context = make(map[string]interface{})
	}
	b.config.Input.Context[key] = value
	return b
}

// WithCustomConfig adds custom configuration
func (b *Builder) WithCustomConfig(key string, value interface{}) *Builder {
	if b.config.CustomConfig == nil {
		b.config.CustomConfig = make(map[string]interface{})
	}
	b.config.CustomConfig[key] = value
	return b
}

// WithFiles adds input files
func (b *Builder) WithFiles(files []golem.FileInfo) *Builder {
	b.config.Input.Files = files
	return b
}

// Build creates the task
func (b *Builder) Build() golem.Task {
	return NewTask(b.config.Name, b.config)
}

// CreateResearchTask creates a research task
func CreateResearchTask(name, query string, agentID string) golem.Task {
	return NewBuilder(name).
		WithDescription("Research task to gather information about a specific topic").
		WithAssignedAgent(agentID).
		WithInputText(query).
		WithInputParameter("task_type", "research").
		WithRequiredTools([]string{"search", "wikipedia"}).
		WithTimeout(10 * time.Minute).
		Build()
}

// CreateAnalysisTask creates an analysis task
func CreateAnalysisTask(name, data string, agentID string) golem.Task {
	return NewBuilder(name).
		WithDescription("Analysis task to analyze provided data and extract insights").
		WithAssignedAgent(agentID).
		WithInputText(data).
		WithInputParameter("task_type", "analysis").
		WithTimeout(15 * time.Minute).
		Build()
}

// CreateWritingTask creates a writing task
func CreateWritingTask(name, prompt string, agentID string, wordCount int) golem.Task {
	return NewBuilder(name).
		WithDescription("Writing task to generate content based on the given prompt").
		WithAssignedAgent(agentID).
		WithInputText(prompt).
		WithInputParameter("task_type", "writing").
		WithInputParameter("word_count", wordCount).
		WithTimeout(20 * time.Minute).
		Build()
}

// CreateCalculationTask creates a calculation task
func CreateCalculationTask(name, expression string, agentID string) golem.Task {
	return NewBuilder(name).
		WithDescription("Calculation task to perform mathematical operations").
		WithAssignedAgent(agentID).
		WithInputText(expression).
		WithInputParameter("task_type", "calculation").
		WithRequiredTools([]string{"calculator"}).
		WithTimeout(5 * time.Minute).
		Build()
}

// CreateSummarizationTask creates a summarization task
func CreateSummarizationTask(name, content string, agentID string, maxLength int) golem.Task {
	return NewBuilder(name).
		WithDescription("Summarization task to create a concise summary of the provided content").
		WithAssignedAgent(agentID).
		WithInputText(content).
		WithInputParameter("task_type", "summarization").
		WithInputParameter("max_length", maxLength).
		WithTimeout(10 * time.Minute).
		Build()
}

// CreateTranslationTask creates a translation task
func CreateTranslationTask(name, text, targetLanguage, agentID string) golem.Task {
	return NewBuilder(name).
		WithDescription("Translation task to translate text from one language to another").
		WithAssignedAgent(agentID).
		WithInputText(text).
		WithInputParameter("task_type", "translation").
		WithInputParameter("target_language", targetLanguage).
		WithTimeout(10 * time.Minute).
		Build()
}

// Validate validates the task configuration
func (t *task) Validate() error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.name == "" {
		return fmt.Errorf("task name is required")
	}

	if t.description == "" {
		return fmt.Errorf("task description is required")
	}

	agentID := t.config.CustomConfig["agent_id"]
	if agentID == nil || agentID.(string) == "" {
		return fmt.Errorf("task must be assigned to an agent")
	}

	if t.config.Timeout <= 0 {
		return fmt.Errorf("task timeout must be positive")
	}

	if t.config.RetryCount < 0 {
		return fmt.Errorf("task retry count must be non-negative")
	}

	return nil
}

// GetAssignedAgent returns the assigned agent ID
func (t *task) GetAssignedAgent() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if agentID, exists := t.config.CustomConfig["agent_id"]; exists {
		if agentIDStr, ok := agentID.(string); ok {
			return agentIDStr
		}
	}

	return ""
}

// GetCreatedAt returns the creation time
func (t *task) GetCreatedAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.createdAt
}

// GetUpdatedAt returns the last update time
func (t *task) GetUpdatedAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.updatedAt
}

// Clone creates a copy of the task
func (t *task) Clone() golem.Task {
	t.mu.RLock()
	defer t.mu.RUnlock()

	clone := &task{
		id:           uuid.New().String(),
		name:         t.name,
		description:  t.description,
		input:        t.input,
		config:       t.config,
		dependencies: make([]string, len(t.dependencies)),
		status:       golem.TaskStatusPending,
		createdAt:    time.Now(),
		updatedAt:    time.Now(),
	}

	copy(clone.dependencies, t.dependencies)
	return clone
}

// GetDuration returns the task execution duration if completed
func (t *task) GetDuration() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.result != nil {
		return t.result.Duration
	}
	return 0
}

// IsCompleted checks if the task is completed
func (t *task) IsCompleted() bool {
	return t.GetStatus() == golem.TaskStatusCompleted
}

// IsFailed checks if the task failed
func (t *task) IsFailed() bool {
	return t.GetStatus() == golem.TaskStatusFailed
}

// IsPending checks if the task is pending
func (t *task) IsPending() bool {
	return t.GetStatus() == golem.TaskStatusPending
}

// IsRunning checks if the task is running
func (t *task) IsRunning() bool {
	return t.GetStatus() == golem.TaskStatusRunning
}

// AddDependency adds a dependency to the task
func (t *task) AddDependency(taskID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, dep := range t.dependencies {
		if dep == taskID {
			return
		}
	}

	t.dependencies = append(t.dependencies, taskID)
	t.updatedAt = time.Now()
}

// RemoveDependency removes a dependency from the task
func (t *task) RemoveDependency(taskID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for i, dep := range t.dependencies {
		if dep == taskID {
			t.dependencies = append(t.dependencies[:i], t.dependencies[i+1:]...)
			t.updatedAt = time.Now()
			break
		}
	}
}

// GetMetadata returns task metadata
func (t *task) GetMetadata() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	metadata := map[string]interface{}{
		"id":             t.id,
		"name":           t.name,
		"description":    t.description,
		"status":         t.status.String(),
		"assigned_agent": t.GetAssignedAgent(),
		"dependencies":   t.dependencies,
		"required_tools": t.config.RequiredTools,
		"priority":       t.config.Priority,
		"retry_count":    t.config.RetryCount,
		"timeout":        t.config.Timeout,
		"created_at":     t.createdAt,
		"updated_at":     t.updatedAt,
	}

	if t.result != nil {
		metadata["completed_at"] = t.result.CreatedAt
		metadata["duration"] = t.result.Duration
		metadata["tokens_used"] = t.result.TokensUsed
		metadata["success"] = t.result.Success
	}

	return metadata
}
