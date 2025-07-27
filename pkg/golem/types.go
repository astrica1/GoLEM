package golem

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Agent interface {
	ID() string
	Name() string
	Role() string
	Execute(ctx context.Context, task Task) (*TaskResult, error)
	Configure(config AgentConfig) error
	GetCapabilities() []Capability
	GetMemory() Memory
	IsHealthy(ctx context.Context) bool
}

type Task interface {
	ID() string
	Name() string
	Description() string
	GetInput() TaskInput
	GetConfig() TaskConfig
	GetDependencies() []string
	SetResult(result *TaskResult)
	GetResult() *TaskResult
	GetStatus() TaskStatus
	SetStatus(status TaskStatus)
}

type LLMProvider interface {
	Name() string
	GenerateResponse(ctx context.Context, req *GenerationRequest) (*GenerationResponse, error)
	GenerateStream(ctx context.Context, req *GenerationRequest, callback StreamCallback) error
	GetModels(ctx context.Context) ([]Model, error)
	GetTokenCount(text string, model string) (int, error)
	ValidateConfig(config map[string]interface{}) error
}

type Memory interface {
	Store(ctx context.Context, key string, data interface{}) error
	Retrieve(ctx context.Context, key string) (interface{}, error)
	Delete(ctx context.Context, key string) error
	Search(ctx context.Context, query string, limit int) ([]MemoryItem, error)
	GetConversationHistory(ctx context.Context, agentID string, limit int) ([]ConversationItem, error)
	AddToConversation(ctx context.Context, agentID string, item ConversationItem) error
	Clear(ctx context.Context) error
}

type Tool interface {
	Name() string
	Description() string
	GetSchema() ToolSchema
	Execute(ctx context.Context, params map[string]interface{}) (interface{}, error)
	ValidateParams(params map[string]interface{}) error
}

type Workflow interface {
	ID() string
	Name() string
	AddTask(task Task) error
	RemoveTask(taskID string) error
	Execute(ctx context.Context) (*WorkflowResult, error)
	GetStatus() WorkflowStatus
	GetTasks() []Task
	GetDAG() *DAG
	Validate() error
}

type Engine interface {
	RegisterAgent(agent Agent) error
	UnregisterAgent(agentID string) error
	GetAgent(agentID string) (Agent, error)
	ListAgents() []Agent
	CreateWorkflow(name string, config WorkflowConfig) Workflow
	ExecuteTask(ctx context.Context, task Task) (*TaskResult, error)
	ExecuteWorkflow(ctx context.Context, workflow Workflow) (*WorkflowResult, error)
	GetMetrics() EngineMetrics
	Shutdown(ctx context.Context) error
	IsHealthy() bool
}

type TaskStatus int

const (
	TaskStatusPending TaskStatus = iota
	TaskStatusRunning
	TaskStatusCompleted
	TaskStatusFailed
	TaskStatusCancelled
	TaskStatusSkipped
)

type WorkflowStatus int

const (
	WorkflowStatusPending WorkflowStatus = iota
	WorkflowStatusRunning
	WorkflowStatusCompleted
	WorkflowStatusFailed
	WorkflowStatusCancelled
	WorkflowStatusPartiallyCompleted
)

type StreamCallback func(chunk *StreamChunk) error

type AgentConfig struct {
	Name         string                 `json:"name" yaml:"name"`
	Role         string                 `json:"role" yaml:"role"`
	LLMProvider  string                 `json:"llm_provider" yaml:"llm_provider"`
	Model        string                 `json:"model" yaml:"model"`
	Temperature  float32                `json:"temperature" yaml:"temperature"`
	MaxTokens    int                    `json:"max_tokens" yaml:"max_tokens"`
	Tools        []string               `json:"tools" yaml:"tools"`
	Memory       MemoryConfig           `json:"memory" yaml:"memory"`
	CustomConfig map[string]interface{} `json:"custom_config" yaml:"custom_config"`
}

type TaskConfig struct {
	Priority      int                    `json:"priority" yaml:"priority"`
	Timeout       time.Duration          `json:"timeout" yaml:"timeout"`
	RetryCount    int                    `json:"retry_count" yaml:"retry_count"`
	RequiredTools []string               `json:"required_tools" yaml:"required_tools"`
	CustomConfig  map[string]interface{} `json:"custom_config" yaml:"custom_config"`
}

type WorkflowConfig struct {
	MaxConcurrency int                    `json:"max_concurrency" yaml:"max_concurrency"`
	Timeout        time.Duration          `json:"timeout" yaml:"timeout"`
	FailurePolicy  FailurePolicy          `json:"failure_policy" yaml:"failure_policy"`
	CustomConfig   map[string]interface{} `json:"custom_config" yaml:"custom_config"`
}

type MemoryConfig struct {
	Backend      string                 `json:"backend" yaml:"backend"`
	MaxSize      int                    `json:"max_size" yaml:"max_size"`
	TTL          time.Duration          `json:"ttl" yaml:"ttl"`
	EnableSearch bool                   `json:"enable_search" yaml:"enable_search"`
	Config       map[string]interface{} `json:"config" yaml:"config"`
}

type TaskInput struct {
	Text       string                 `json:"text" yaml:"text"`
	Files      []FileInfo             `json:"files" yaml:"files"`
	Parameters map[string]interface{} `json:"parameters" yaml:"parameters"`
	Context    map[string]interface{} `json:"context" yaml:"context"`
}

type TaskResult struct {
	ID         string                 `json:"id" yaml:"id"`
	TaskID     string                 `json:"task_id" yaml:"task_id"`
	AgentID    string                 `json:"agent_id" yaml:"agent_id"`
	Output     string                 `json:"output" yaml:"output"`
	Metadata   map[string]interface{} `json:"metadata" yaml:"metadata"`
	TokensUsed int                    `json:"tokens_used" yaml:"tokens_used"`
	Duration   time.Duration          `json:"duration" yaml:"duration"`
	Success    bool                   `json:"success" yaml:"success"`
	Error      string                 `json:"error,omitempty" yaml:"error,omitempty"`
	CreatedAt  time.Time              `json:"created_at" yaml:"created_at"`
}

type WorkflowResult struct {
	ID          string                 `json:"id" yaml:"id"`
	WorkflowID  string                 `json:"workflow_id" yaml:"workflow_id"`
	TaskResults []TaskResult           `json:"task_results" yaml:"task_results"`
	Status      WorkflowStatus         `json:"status" yaml:"status"`
	Duration    time.Duration          `json:"duration" yaml:"duration"`
	Metadata    map[string]interface{} `json:"metadata" yaml:"metadata"`
	Error       string                 `json:"error,omitempty" yaml:"error,omitempty"`
	CreatedAt   time.Time              `json:"created_at" yaml:"created_at"`
}

type GenerationRequest struct {
	Prompt      string                 `json:"prompt" yaml:"prompt"`
	Model       string                 `json:"model" yaml:"model"`
	Temperature float32                `json:"temperature" yaml:"temperature"`
	MaxTokens   int                    `json:"max_tokens" yaml:"max_tokens"`
	SystemMsg   string                 `json:"system_message" yaml:"system_message"`
	Tools       []ToolDefinition       `json:"tools" yaml:"tools"`
	Context     map[string]interface{} `json:"context" yaml:"context"`
}

type GenerationResponse struct {
	Text         string                 `json:"text" yaml:"text"`
	ToolCalls    []ToolCall             `json:"tool_calls" yaml:"tool_calls"`
	TokensUsed   int                    `json:"tokens_used" yaml:"tokens_used"`
	Model        string                 `json:"model" yaml:"model"`
	FinishReason string                 `json:"finish_reason" yaml:"finish_reason"`
	Metadata     map[string]interface{} `json:"metadata" yaml:"metadata"`
}

type StreamChunk struct {
	Text       string                 `json:"text" yaml:"text"`
	Delta      string                 `json:"delta" yaml:"delta"`
	IsComplete bool                   `json:"is_complete" yaml:"is_complete"`
	ToolCall   *ToolCall              `json:"tool_call,omitempty" yaml:"tool_call,omitempty"`
	Metadata   map[string]interface{} `json:"metadata" yaml:"metadata"`
}

type Model struct {
	ID           string   `json:"id" yaml:"id"`
	Name         string   `json:"name" yaml:"name"`
	Provider     string   `json:"provider" yaml:"provider"`
	Capabilities []string `json:"capabilities" yaml:"capabilities"`
	MaxTokens    int      `json:"max_tokens" yaml:"max_tokens"`
	CostPer1K    float64  `json:"cost_per_1k" yaml:"cost_per_1k"`
}

type Capability struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Tools       []string `json:"tools" yaml:"tools"`
	Required    bool     `json:"required" yaml:"required"`
}

type MemoryItem struct {
	ID        string                 `json:"id" yaml:"id"`
	Key       string                 `json:"key" yaml:"key"`
	Data      interface{}            `json:"data" yaml:"data"`
	Metadata  map[string]interface{} `json:"metadata" yaml:"metadata"`
	Score     float64                `json:"score" yaml:"score"`
	CreatedAt time.Time              `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" yaml:"updated_at"`
}

type ConversationItem struct {
	ID        string                 `json:"id" yaml:"id"`
	AgentID   string                 `json:"agent_id" yaml:"agent_id"`
	Role      string                 `json:"role" yaml:"role"` // [user, assistant, system]
	Content   string                 `json:"content" yaml:"content"`
	Metadata  map[string]interface{} `json:"metadata" yaml:"metadata"`
	Timestamp time.Time              `json:"timestamp" yaml:"timestamp"`
}

type ToolDefinition struct {
	Name        string     `json:"name" yaml:"name"`
	Description string     `json:"description" yaml:"description"`
	Parameters  ToolSchema `json:"parameters" yaml:"parameters"`
}

type ToolCall struct {
	ID         string                 `json:"id" yaml:"id"`
	Name       string                 `json:"name" yaml:"name"`
	Parameters map[string]interface{} `json:"parameters" yaml:"parameters"`
}

type ToolSchema struct {
	Type        string                        `json:"type" yaml:"type"`
	Description string                        `json:"description" yaml:"description"`
	Properties  map[string]ToolSchemaProperty `json:"properties" yaml:"properties"`
	Required    []string                      `json:"required" yaml:"required"`
}

type ToolSchemaProperty struct {
	Type        string      `json:"type" yaml:"type"`
	Description string      `json:"description" yaml:"description"`
	Default     interface{} `json:"default,omitempty" yaml:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty" yaml:"enum,omitempty"`
	Items       interface{} `json:"items,omitempty" yaml:"items,omitempty"`
}

type FileInfo struct {
	Name string `json:"name" yaml:"name"`
	Path string `json:"path" yaml:"path"`
	Size int64  `json:"size" yaml:"size"`
	Type string `json:"type" yaml:"type"`
}

type DAG struct {
	Nodes []DAGNode `json:"nodes" yaml:"nodes"`
	Edges []DAGEdge `json:"edges" yaml:"edges"`
}

type DAGNode struct {
	ID       string            `json:"id" yaml:"id"`
	TaskID   string            `json:"task_id" yaml:"task_id"`
	Metadata map[string]string `json:"metadata" yaml:"metadata"`
}

type DAGEdge struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`
}

type EngineMetrics struct {
	ActiveAgents   int                    `json:"active_agents" yaml:"active_agents"`
	ActiveTasks    int                    `json:"active_tasks" yaml:"active_tasks"`
	CompletedTasks int64                  `json:"completed_tasks" yaml:"completed_tasks"`
	FailedTasks    int64                  `json:"failed_tasks" yaml:"failed_tasks"`
	AverageLatency time.Duration          `json:"average_latency" yaml:"average_latency"`
	TokensUsed     int64                  `json:"tokens_used" yaml:"tokens_used"`
	CostEstimate   float64                `json:"cost_estimate" yaml:"cost_estimate"`
	CustomMetrics  map[string]interface{} `json:"custom_metrics" yaml:"custom_metrics"`
}

type FailurePolicy int

const (
	FailurePolicyStopOnError FailurePolicy = iota
	FailurePolicyContinueOnError
	FailurePolicyRetryOnError
	FailurePolicySkipOnError
)

type EventType int

const (
	EventTypeTaskStarted EventType = iota
	EventTypeTaskCompleted
	EventTypeTaskFailed
	EventTypeWorkflowStarted
	EventTypeWorkflowCompleted
	EventTypeWorkflowFailed
	EventTypeAgentRegistered
	EventTypeAgentUnregistered
)

type Event struct {
	ID        string                 `json:"id" yaml:"id"`
	Type      EventType              `json:"type" yaml:"type"`
	Source    string                 `json:"source" yaml:"source"`
	Data      map[string]interface{} `json:"data" yaml:"data"`
	Timestamp time.Time              `json:"timestamp" yaml:"timestamp"`
}

type EventHandler func(event Event) error

type EventBus interface {
	Subscribe(eventType EventType, handler EventHandler) error
	Unsubscribe(eventType EventType, handler EventHandler) error
	Publish(event Event) error
	Close() error
}

func NewUUID() string {
	return uuid.New().String()
}

func NewTaskResult(taskID, agentID string) *TaskResult {
	return &TaskResult{
		ID:        NewUUID(),
		TaskID:    taskID,
		AgentID:   agentID,
		CreatedAt: time.Now(),
	}
}

func NewWorkflowResult(workflowID string) *WorkflowResult {
	return &WorkflowResult{
		ID:          NewUUID(),
		WorkflowID:  workflowID,
		TaskResults: make([]TaskResult, 0),
		CreatedAt:   time.Now(),
	}
}

func (s TaskStatus) String() string {
	switch s {
	case TaskStatusPending:
		return "pending"
	case TaskStatusRunning:
		return "running"
	case TaskStatusCompleted:
		return "completed"
	case TaskStatusFailed:
		return "failed"
	case TaskStatusCancelled:
		return "cancelled"
	case TaskStatusSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

func (s WorkflowStatus) String() string {
	switch s {
	case WorkflowStatusPending:
		return "pending"
	case WorkflowStatusRunning:
		return "running"
	case WorkflowStatusCompleted:
		return "completed"
	case WorkflowStatusFailed:
		return "failed"
	case WorkflowStatusCancelled:
		return "cancelled"
	case WorkflowStatusPartiallyCompleted:
		return "partially_completed"
	default:
		return "unknown"
	}
}

func (f FailurePolicy) String() string {
	switch f {
	case FailurePolicyStopOnError:
		return "stop_on_error"
	case FailurePolicyContinueOnError:
		return "continue_on_error"
	case FailurePolicyRetryOnError:
		return "retry_on_error"
	case FailurePolicySkipOnError:
		return "skip_on_error"
	default:
		return "unknown"
	}
}

func (e EventType) String() string {
	switch e {
	case EventTypeTaskStarted:
		return "task_started"
	case EventTypeTaskCompleted:
		return "task_completed"
	case EventTypeTaskFailed:
		return "task_failed"
	case EventTypeWorkflowStarted:
		return "workflow_started"
	case EventTypeWorkflowCompleted:
		return "workflow_completed"
	case EventTypeWorkflowFailed:
		return "workflow_failed"
	case EventTypeAgentRegistered:
		return "agent_registered"
	case EventTypeAgentUnregistered:
		return "agent_unregistered"
	default:
		return "unknown"
	}
}

type LLMRequest struct {
	Messages    []ChatMessage          `json:"messages" yaml:"messages"`
	Model       string                 `json:"model" yaml:"model"`
	Temperature float32                `json:"temperature" yaml:"temperature"`
	MaxTokens   int                    `json:"max_tokens" yaml:"max_tokens"`
	Tools       []Tool                 `json:"tools,omitempty" yaml:"tools,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type ChatMessage struct {
	Role     string    `json:"role" yaml:"role"`
	Content  string    `json:"content" yaml:"content"`
	ToolCall *ToolCall `json:"tool_call,omitempty" yaml:"tool_call,omitempty"`
}

type LLMResponse struct {
	Content      string     `json:"content" yaml:"content"`
	Usage        Usage      `json:"usage" yaml:"usage"`
	FinishReason string     `json:"finish_reason" yaml:"finish_reason"`
	ToolCalls    []ToolCall `json:"tool_calls,omitempty" yaml:"tool_calls,omitempty"`
}

type LLMStreamResponse struct {
	Content   string     `json:"content" yaml:"content"`
	Done      bool       `json:"done" yaml:"done"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty" yaml:"tool_calls,omitempty"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens" yaml:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens" yaml:"completion_tokens"`
	TotalTokens      int `json:"total_tokens" yaml:"total_tokens"`
}

type ToolResult struct {
	ToolCallID string      `json:"tool_call_id" yaml:"tool_call_id"`
	Content    string      `json:"content" yaml:"content"`
	Error      error       `json:"error,omitempty" yaml:"error,omitempty"`
	Metadata   interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type ModelInfo struct {
	Name         string `json:"name" yaml:"name"`
	Provider     string `json:"provider" yaml:"provider"`
	MaxTokens    int    `json:"max_tokens" yaml:"max_tokens"`
	SupportsChat bool   `json:"supports_chat" yaml:"supports_chat"`
}
