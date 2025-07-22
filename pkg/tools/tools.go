// Package tools provides built-in tools and tool management for GoLEM.
package tools

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/sirupsen/logrus"
)

var Registry = &ToolRegistry{
	tools: make(map[string]golem.Tool),
}

type ToolRegistry struct {
	tools map[string]golem.Tool
	mu    sync.RWMutex
}

// Register registers a tool with the given name
func (tr *ToolRegistry) Register(name string, tool golem.Tool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.tools[name] = tool
}

// Get retrieves a tool by name
func (tr *ToolRegistry) Get(name string) (golem.Tool, error) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	tool, exists := tr.tools[name]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", name)
	}

	return tool, nil
}

// List returns all registered tool names
func (tr *ToolRegistry) List() []string {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	names := make([]string, 0, len(tr.tools))
	for name := range tr.tools {
		names = append(names, name)
	}

	return names
}

// GetAllTools returns all registered tools
func (tr *ToolRegistry) GetAllTools() map[string]golem.Tool {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	tools := make(map[string]golem.Tool)
	for name, tool := range tr.tools {
		tools[name] = tool
	}

	return tools
}

// Clear removes all tools from the registry
func (tr *ToolRegistry) Clear() {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.tools = make(map[string]golem.Tool)
}

// RegisterTool registers a tool with the global registry
func RegisterTool(name string, tool golem.Tool) {
	Registry.Register(name, tool)
}

// GetTool retrieves a tool from the global registry
func GetTool(name string) (golem.Tool, error) {
	return Registry.Get(name)
}

// ListTools returns all registered tool names from the global registry
func ListTools() []string {
	return Registry.List()
}

// GetAllTools returns all tools from the global registry
func GetAllTools() map[string]golem.Tool {
	return Registry.GetAllTools()
}

type BaseTool struct {
	name        string
	description string
	schema      golem.ToolSchema
}

// NewBaseTool creates a new base tool
func NewBaseTool(name, description string, schema golem.ToolSchema) *BaseTool {
	return &BaseTool{
		name:        name,
		description: description,
		schema:      schema,
	}
}

// Name returns the tool name
func (bt *BaseTool) Name() string {
	return bt.name
}

// Description returns the tool description
func (bt *BaseTool) Description() string {
	return bt.description
}

// GetSchema returns the tool schema
func (bt *BaseTool) GetSchema() golem.ToolSchema {
	return bt.schema
}

// ValidateParams validates parameters against the schema
func (bt *BaseTool) ValidateParams(params map[string]interface{}) error {
	for _, required := range bt.schema.Required {
		if _, exists := params[required]; !exists {
			return fmt.Errorf("required parameter %s is missing", required)
		}
	}

	for paramName, paramValue := range params {
		propSchema, exists := bt.schema.Properties[paramName]
		if !exists {
			continue
		}

		if err := validateParameterType(paramName, paramValue, propSchema); err != nil {
			return err
		}
	}

	return nil
}

// validateParameterType validates a parameter against its schema
func validateParameterType(name string, value interface{}, schema golem.ToolSchemaProperty) error {
	switch schema.Type {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("parameter %s must be a string", name)
		}

		if len(schema.Enum) > 0 {
			strVal := value.(string)
			for _, enumVal := range schema.Enum {
				if strVal == enumVal {
					return nil
				}
			}
			return fmt.Errorf("parameter %s must be one of: %v", name, schema.Enum)
		}

	case "number":
		switch value.(type) {
		case int, int32, int64, float32, float64:
		default:
			return fmt.Errorf("parameter %s must be a number", name)
		}

	case "integer":
		switch value.(type) {
		case int, int32, int64:
		default:
			return fmt.Errorf("parameter %s must be an integer", name)
		}

	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("parameter %s must be a boolean", name)
		}

	case "array":
		// TODO: Handle array items validation
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("parameter %s must be an array", name)
		}

	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("parameter %s must be an object", name)
		}
	}

	return nil
}

// ToolManager manages tools for agents
type ToolManager struct {
	tools map[string]golem.Tool
	mu    sync.RWMutex
}

// NewToolManager creates a new tool manager
func NewToolManager() *ToolManager {
	return &ToolManager{
		tools: make(map[string]golem.Tool),
	}
}

// AddTool adds a tool to the manager
func (tm *ToolManager) AddTool(tool golem.Tool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tools[tool.Name()] = tool
}

// RemoveTool removes a tool from the manager
func (tm *ToolManager) RemoveTool(name string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.tools, name)
}

// GetTool gets a tool by name
func (tm *ToolManager) GetTool(name string) (golem.Tool, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tool, exists := tm.tools[name]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", name)
	}

	return tool, nil
}

// ListTools returns all tool names
func (tm *ToolManager) ListTools() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	names := make([]string, 0, len(tm.tools))
	for name := range tm.tools {
		names = append(names, name)
	}

	return names
}

// ExecuteTool executes a tool with the given parameters
func (tm *ToolManager) ExecuteTool(ctx context.Context, name string, params map[string]interface{}) (interface{}, error) {
	tool, err := tm.GetTool(name)
	if err != nil {
		return nil, err
	}

	return tool.Execute(ctx, params)
}

// HasTool checks if a tool is available
func (tm *ToolManager) HasTool(name string) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, exists := tm.tools[name]
	return exists
}

// GetAllTools returns all tools
func (tm *ToolManager) GetAllTools() map[string]golem.Tool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tools := make(map[string]golem.Tool)
	for name, tool := range tm.tools {
		tools[name] = tool
	}

	return tools
}

// Clear removes all tools
func (tm *ToolManager) Clear() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tools = make(map[string]golem.Tool)
}

// LoadBuiltinTools loads all built-in tools into the manager
func (tm *ToolManager) LoadBuiltinTools() {
	// Load all built-in tools
	tm.AddTool(NewCalculatorTool())
	tm.AddTool(NewSearchTool())
	tm.AddTool(NewWikipediaTool())
	tm.AddTool(NewFileSystemTool())
	tm.AddTool(NewHTTPTool())
	tm.AddTool(NewDateTimeTool())
	tm.AddTool(NewTextProcessingTool())
	tm.AddTool(NewSystemInfoTool())
}

// ToolExecutionResult represents the result of tool execution
type ToolExecutionResult struct {
	ToolName string        `json:"tool_name"`
	Success  bool          `json:"success"`
	Result   interface{}   `json:"result,omitempty"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

// ExecuteToolSafely executes a tool with error handling and recovery
func ExecuteToolSafely(ctx context.Context, tool golem.Tool, params map[string]interface{}) *ToolExecutionResult {
	start := time.Now()

	result := &ToolExecutionResult{
		ToolName: tool.Name(),
		Duration: 0,
		Success:  false,
	}

	// Recover from panics
	defer func() {
		result.Duration = time.Since(start)
		if r := recover(); r != nil {
			result.Error = fmt.Sprintf("tool panic: %v", r)
			result.Success = false
		}
	}()

	// Validate parameters
	if err := tool.ValidateParams(params); err != nil {
		result.Error = fmt.Sprintf("parameter validation failed: %v", err)
		return result
	}

	// Execute tool
	output, err := tool.Execute(ctx, params)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Result = output
	result.Success = true
	return result
}

// Custom tool interface for tools that need initialization
type InitializableTool interface {
	golem.Tool
	Initialize(config map[string]interface{}) error
}

// Custom tool interface for tools that need cleanup
type CleanupTool interface {
	golem.Tool
	Cleanup() error
}

// AdvancedToolManager provides additional functionality for managing tools
type AdvancedToolManager struct {
	*ToolManager
	initConfigs map[string]map[string]interface{}
	logger      *logrus.Logger
}

// NewAdvancedToolManager creates a new advanced tool manager
func NewAdvancedToolManager() *AdvancedToolManager {
	return &AdvancedToolManager{
		ToolManager: NewToolManager(),
		initConfigs: make(map[string]map[string]interface{}),
		logger:      logrus.New(),
	}
}

// AddToolWithConfig adds a tool with initialization configuration
func (atm *AdvancedToolManager) AddToolWithConfig(tool golem.Tool, config map[string]interface{}) error {
	// Initialize tool if it supports initialization
	if initTool, ok := tool.(InitializableTool); ok {
		if err := initTool.Initialize(config); err != nil {
			return fmt.Errorf("failed to initialize tool %s: %w", tool.Name(), err)
		}
		atm.initConfigs[tool.Name()] = config
	}

	atm.AddTool(tool)
	atm.logger.WithField("tool", tool.Name()).Info("Tool added with configuration")
	return nil
}

// RemoveToolWithCleanup removes a tool and performs cleanup if supported
func (atm *AdvancedToolManager) RemoveToolWithCleanup(name string) error {
	tool, err := atm.GetTool(name)
	if err != nil {
		return err
	}

	// Cleanup tool if it supports cleanup
	if cleanupTool, ok := tool.(CleanupTool); ok {
		if err := cleanupTool.Cleanup(); err != nil {
			atm.logger.WithError(err).WithField("tool", name).Warn("Tool cleanup failed")
		}
	}

	atm.RemoveTool(name)
	delete(atm.initConfigs, name)
	atm.logger.WithField("tool", name).Info("Tool removed with cleanup")
	return nil
}

// Shutdown performs cleanup for all tools that support it
func (atm *AdvancedToolManager) Shutdown() error {
	for name, tool := range atm.GetAllTools() {
		if cleanupTool, ok := tool.(CleanupTool); ok {
			if err := cleanupTool.Cleanup(); err != nil {
				atm.logger.WithError(err).WithField("tool", name).Warn("Tool cleanup failed during shutdown")
			}
		}
	}

	atm.Clear()
	atm.logger.Info("Advanced tool manager shut down")
	return nil
}

// init registers built-in tools
func init() {
	RegisterTool("calculator", NewCalculatorTool())
	RegisterTool("search", NewSearchTool())
	RegisterTool("wikipedia", NewWikipediaTool())
	RegisterTool("filesystem", NewFileSystemTool())
	RegisterTool("http", NewHTTPTool())
	RegisterTool("datetime", NewDateTimeTool())
	RegisterTool("text", NewTextProcessingTool())
	RegisterTool("system", NewSystemInfoTool())
}
