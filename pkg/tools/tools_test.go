package tools

import (
	"context"
	"fmt"
	"testing"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToolRegistry_Basic(t *testing.T) {
	Registry.Clear()

	tools := ListTools()
	assert.Empty(t, tools)
}

func TestToolRegistry_RegisterTool(t *testing.T) {
	Registry.Clear()

	tool := &MockTool{
		name:        "test-tool",
		description: "A test tool",
		schema: golem.ToolSchema{
			Type:        "object",
			Description: "Test tool schema",
			Properties: map[string]golem.ToolSchemaProperty{
				"input": {
					Type:        "string",
					Description: "Input parameter",
				},
			},
			Required: []string{"input"},
		},
	}

	RegisterTool("test-tool", tool)

	tools := ListTools()
	assert.Len(t, tools, 1)
	assert.Contains(t, tools, "test-tool")
}

func TestToolRegistry_GetTool(t *testing.T) {
	Registry.Clear()

	tool := &MockTool{
		name: "get-tool",
		schema: golem.ToolSchema{
			Type: "object",
		},
	}

	RegisterTool("get-tool", tool)

	retrieved, err := GetTool("get-tool")
	require.NoError(t, err)
	assert.Equal(t, tool, retrieved)

	_, err = GetTool("non-existent")
	assert.Error(t, err)
}

func TestBuiltInTools(t *testing.T) {
	calc := NewCalculatorTool()
	assert.Equal(t, "calculator", calc.Name())
	assert.NotEmpty(t, calc.Description())

	schema := calc.GetSchema()
	assert.Equal(t, "object", schema.Type)
	assert.Contains(t, schema.Properties, "expression")
	assert.Contains(t, schema.Required, "expression")

	search := NewSearchTool()
	assert.Equal(t, "search", search.Name())
	assert.NotEmpty(t, search.Description())

	fs := NewFileSystemTool()
	assert.Equal(t, "filesystem", fs.Name())
	assert.NotEmpty(t, fs.Description())
}

type MockTool struct {
	name        string
	description string
	schema      golem.ToolSchema
	executeFunc func(context.Context, map[string]interface{}) (interface{}, error)
}

func (m *MockTool) Name() string {
	return m.name
}

func (m *MockTool) Description() string {
	if m.description == "" {
		return "Mock tool for testing"
	}
	return m.description
}

func (m *MockTool) GetSchema() golem.ToolSchema {
	return m.schema
}

func (m *MockTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, params)
	}
	return "Mock execution result", nil
}

func (m *MockTool) ValidateParams(params map[string]interface{}) error {
	for _, required := range m.schema.Required {
		if _, exists := params[required]; !exists {
			return fmt.Errorf("required parameter %s is missing", required)
		}
	}
	return nil
}

func TestMockTool_Validation(t *testing.T) {
	tool := &MockTool{
		name: "validation-test",
		schema: golem.ToolSchema{
			Properties: map[string]golem.ToolSchemaProperty{
				"required_param": {
					Type:        "string",
					Description: "A required parameter",
				},
			},
			Required: []string{"required_param"},
		},
	}

	err := tool.ValidateParams(map[string]interface{}{
		"required_param": "value",
	})
	assert.NoError(t, err)

	err = tool.ValidateParams(map[string]interface{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required_param")
}

func BenchmarkToolRegistry_RegisterTool(b *testing.B) {
	Registry.Clear()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool := &MockTool{
			name:   fmt.Sprintf("benchmark-tool-%d", i),
			schema: golem.ToolSchema{Type: "object"},
		}
		RegisterTool(fmt.Sprintf("benchmark-tool-%d", i), tool)
	}
}

func BenchmarkToolRegistry_GetTool(b *testing.B) {
	Registry.Clear()

	const numTools = 1000
	for i := 0; i < numTools; i++ {
		tool := &MockTool{
			name:   fmt.Sprintf("bench-tool-%d", i),
			schema: golem.ToolSchema{Type: "object"},
		}
		RegisterTool(fmt.Sprintf("bench-tool-%d", i), tool)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		toolName := fmt.Sprintf("bench-tool-%d", i%numTools)
		_, err := GetTool(toolName)
		if err != nil {
			b.Fatalf("Failed to get tool: %v", err)
		}
	}
}
