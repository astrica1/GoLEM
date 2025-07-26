package agent

import (
	"context"
	"testing"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockLLMProvider struct {
	mock.Mock
}

func (m *MockLLMProvider) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockLLMProvider) GenerateResponse(ctx context.Context, req *golem.GenerationRequest) (*golem.GenerationResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*golem.GenerationResponse), args.Error(1)
}

func (m *MockLLMProvider) GenerateStream(ctx context.Context, req *golem.GenerationRequest, callback golem.StreamCallback) error {
	args := m.Called(ctx, req, callback)
	return args.Error(0)
}

func (m *MockLLMProvider) GetModels(ctx context.Context) ([]golem.Model, error) {
	args := m.Called(ctx)
	return args.Get(0).([]golem.Model), args.Error(1)
}

func (m *MockLLMProvider) GetTokenCount(text string, model string) (int, error) {
	args := m.Called(text, model)
	return args.Int(0), args.Error(1)
}

func (m *MockLLMProvider) ValidateConfig(config map[string]interface{}) error {
	args := m.Called(config)
	return args.Error(0)
}

type MockMemory struct {
	mock.Mock
}

func (m *MockMemory) Store(ctx context.Context, key string, data interface{}) error {
	args := m.Called(ctx, key, data)
	return args.Error(0)
}

func (m *MockMemory) Retrieve(ctx context.Context, key string) (interface{}, error) {
	args := m.Called(ctx, key)
	return args.Get(0), args.Error(1)
}

func (m *MockMemory) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockMemory) Search(ctx context.Context, query string, limit int) ([]golem.MemoryItem, error) {
	args := m.Called(ctx, query, limit)
	return args.Get(0).([]golem.MemoryItem), args.Error(1)
}

func (m *MockMemory) GetConversationHistory(ctx context.Context, agentID string, limit int) ([]golem.ConversationItem, error) {
	args := m.Called(ctx, agentID, limit)
	return args.Get(0).([]golem.ConversationItem), args.Error(1)
}

func (m *MockMemory) AddToConversation(ctx context.Context, agentID string, item golem.ConversationItem) error {
	args := m.Called(ctx, agentID, item)
	return args.Error(0)
}

func (m *MockMemory) Clear(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockTask struct {
	mock.Mock
}

func (m *MockTask) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockTask) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockTask) Description() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockTask) GetInput() golem.TaskInput {
	args := m.Called()
	return args.Get(0).(golem.TaskInput)
}

func (m *MockTask) GetConfig() golem.TaskConfig {
	args := m.Called()
	return args.Get(0).(golem.TaskConfig)
}

func (m *MockTask) GetDependencies() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockTask) SetResult(result *golem.TaskResult) {
	m.Called(result)
}

func (m *MockTask) GetResult() *golem.TaskResult {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*golem.TaskResult)
}

func (m *MockTask) GetStatus() golem.TaskStatus {
	args := m.Called()
	return args.Get(0).(golem.TaskStatus)
}

func (m *MockTask) SetStatus(status golem.TaskStatus) {
	m.Called(status)
}

func TestNewAgent(t *testing.T) {
	mockLLM := &MockLLMProvider{}
	mockLLM.On("Name").Return("test-provider")

	config := Config{
		Name:        "Test Agent",
		Role:        "Assistant",
		LLMProvider: mockLLM,
		Temperature: 0.7,
		MaxTokens:   1000,
		Memory: golem.MemoryConfig{
			Backend: "memory",
			MaxSize: 1000,
		},
	}

	agent := NewAgent("test-agent", config)
	assert.NotNil(t, agent)
	assert.Equal(t, "Test Agent", agent.Name())
	assert.Equal(t, "Assistant", agent.Role())
	assert.NotEmpty(t, agent.ID())
}

func TestAgentExecute(t *testing.T) {
	mockLLM := &MockLLMProvider{}
	mockTask := &MockTask{}

	mockLLM.On("GenerateResponse", mock.Anything, mock.AnythingOfType("*golem.GenerationRequest")).Return(
		&golem.GenerationResponse{
			Text:       "Task completed successfully",
			TokensUsed: 50,
			Model:      "test-model",
		}, nil)

	mockTask.On("ID").Return("task-1")
	mockTask.On("Name").Return("Test Task")
	mockTask.On("Description").Return("A test task")
	mockTask.On("GetInput").Return(golem.TaskInput{
		Text: "Complete this task",
	})

	config := Config{
		Name:        "Test Agent",
		Role:        "Assistant",
		LLMProvider: mockLLM,
		Temperature: 0.7,
		MaxTokens:   1000,
		Memory: golem.MemoryConfig{
			Backend: "memory",
		},
	}

	agent := NewAgent("test-agent", config)

	ctx := context.Background()
	result, err := agent.Execute(ctx, mockTask)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Task completed successfully", result.Output)
	assert.True(t, result.Success)

	mockLLM.AssertExpectations(t)
	mockTask.AssertExpectations(t)
}

func TestAgentExecuteWithError(t *testing.T) {
	mockLLM := &MockLLMProvider{}
	mockTask := &MockTask{}

	mockLLM.On("GenerateResponse", mock.Anything, mock.AnythingOfType("*golem.GenerationRequest")).Return(
		(*golem.GenerationResponse)(nil), assert.AnError)

	mockTask.On("ID").Return("task-1")
	mockTask.On("Name").Return("Test Task")
	mockTask.On("Description").Return("A test task")
	mockTask.On("GetInput").Return(golem.TaskInput{
		Text: "Complete this task",
	})

	config := Config{
		Name:        "Test Agent",
		Role:        "Assistant",
		LLMProvider: mockLLM,
		Temperature: 0.7,
		MaxTokens:   1000,
		Memory: golem.MemoryConfig{
			Backend: "memory",
		},
	}

	agent := NewAgent("test-agent", config)

	ctx := context.Background()
	result, err := agent.Execute(ctx, mockTask)

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)

	mockLLM.AssertExpectations(t)
	mockTask.AssertExpectations(t)
}

func TestAgentConfigure(t *testing.T) {
	mockLLM := &MockLLMProvider{}
	mockLLM.On("Name").Return("test-provider")

	config := Config{
		Name:        "Test Agent",
		Role:        "Assistant",
		LLMProvider: mockLLM,
		Temperature: 0.7,
		MaxTokens:   1000,
	}

	agent := NewAgent("test-agent", config)

	newConfig := golem.AgentConfig{
		Name:        "Updated Agent",
		Role:        "Updated Assistant",
		Temperature: 0.8,
		MaxTokens:   1500,
	}

	err := agent.Configure(newConfig)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Agent", agent.Name())
	assert.Equal(t, "Updated Assistant", agent.Role())
}

func TestAgentIsHealthy(t *testing.T) {
	mockLLM := &MockLLMProvider{}
	mockLLM.On("ValidateConfig", mock.AnythingOfType("map[string]interface {}")).Return(nil)

	config := Config{
		Name:        "Test Agent",
		Role:        "Assistant",
		LLMProvider: mockLLM,
		Temperature: 0.7,
		MaxTokens:   1000,
		Memory: golem.MemoryConfig{
			Backend: "memory",
		},
	}

	agent := NewAgent("test-agent", config)
	ctx := context.Background()

	isHealthy := agent.IsHealthy(ctx)
	assert.True(t, isHealthy)

	mockLLM.AssertExpectations(t)
}

func TestAgentGetCapabilities(t *testing.T) {
	mockLLM := &MockLLMProvider{}
	mockLLM.On("Name").Return("test-provider")

	config := Config{
		Name:        "Test Agent",
		Role:        "Assistant",
		LLMProvider: mockLLM,
		Temperature: 0.7,
		MaxTokens:   1000,
		Tools:       []string{"calculator", "search"},
	}

	agent := NewAgent("test-agent", config)
	capabilities := agent.GetCapabilities()

	assert.NotNil(t, capabilities)
	assert.Len(t, capabilities, 3) // LLM + 2 tools
}

func TestAgentGetMemory(t *testing.T) {
	mockLLM := &MockLLMProvider{}
	mockLLM.On("Name").Return("test-provider")

	config := Config{
		Name:        "Test Agent",
		Role:        "Assistant",
		LLMProvider: mockLLM,
		Memory: golem.MemoryConfig{
			Backend: "memory",
			MaxSize: 1000,
		},
	}

	agent := NewAgent("test-agent", config)
	memory := agent.GetMemory()

	assert.NotNil(t, memory)
}

func BenchmarkAgentExecute(b *testing.B) {
	mockLLM := &MockLLMProvider{}
	mockTask := &MockTask{}

	mockLLM.On("Name").Return("test-provider")
	mockLLM.On("GenerateResponse", mock.Anything, mock.AnythingOfType("*golem.GenerationRequest")).Return(
		&golem.GenerationResponse{
			Text:       "Benchmark result",
			TokensUsed: 10,
		}, nil)

	mockTask.On("ID").Return("benchmark-task")
	mockTask.On("Name").Return("Benchmark Task")
	mockTask.On("Description").Return("Benchmark description")
	mockTask.On("GetInput").Return(golem.TaskInput{Text: "benchmark input"})
	mockTask.On("GetConfig").Return(golem.TaskConfig{})
	mockTask.On("SetResult", mock.Anything).Return()
	mockTask.On("SetStatus", mock.Anything).Return()

	config := Config{
		Name:        "Benchmark Agent",
		LLMProvider: mockLLM,
	}

	agent := NewAgent("benchmark-agent", config)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := agent.Execute(ctx, mockTask)
		if err != nil {
			b.Fatal(err)
		}
	}
}
