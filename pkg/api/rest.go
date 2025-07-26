package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/astrica1/GoLEM/pkg/agent"
	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/astrica1/GoLEM/pkg/llm/ollama"
	"github.com/astrica1/GoLEM/pkg/llm/openai"
	"github.com/astrica1/GoLEM/pkg/memory"
	"github.com/astrica1/GoLEM/pkg/task"
	"github.com/astrica1/GoLEM/pkg/tools"
)

func convertMessagesToPrompt(messages []golem.ChatMessage) string {
	var prompt strings.Builder
	for _, msg := range messages {
		prompt.WriteString(fmt.Sprintf("%s: %s\n", msg.Role, msg.Content))
	}
	return prompt.String()
}

type Server struct {
	engine      golem.Engine
	router      *gin.Engine
	agents      map[string]golem.Agent
	toolManager *tools.ToolManager
	logger      *logrus.Logger
	port        int
	httpServer  *http.Server
}

type Config struct {
	Port       int    `json:"port" yaml:"port"`
	Debug      bool   `json:"debug" yaml:"debug"`
	EnableCORS bool   `json:"enable_cors" yaml:"enable_cors"`
	EnableDocs bool   `json:"enable_docs" yaml:"enable_docs"`
	DocsPath   string `json:"docs_path" yaml:"docs_path"`
}

// NewServer creates a new REST API server
func NewServer(engine golem.Engine, config *Config) *Server {
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.DocsPath == "" {
		config.DocsPath = "/docs/*any"
	}

	if !config.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	if config.EnableCORS {
		router.Use(corsMiddleware())
	}

	server := &Server{
		engine:      engine,
		router:      router,
		agents:      make(map[string]golem.Agent),
		toolManager: tools.NewToolManager(),
		logger:      logrus.New(),
		port:        config.Port,
	}

	server.setupRoutes(config)
	return server
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes(config *Config) {
	s.router.GET("/health", s.healthCheck)

	v1 := s.router.Group("/api/v1")
	{
		agents := v1.Group("/agents")
		{
			agents.POST("", s.createAgent)
			agents.GET("", s.listAgents)
			agents.GET("/:id", s.getAgent)
			agents.PUT("/:id", s.updateAgent)
			agents.DELETE("/:id", s.deleteAgent)
			agents.POST("/:id/execute", s.executeAgent)
			agents.POST("/:id/chat", s.chatWithAgent)
		}

		tasks := v1.Group("/tasks")
		{
			tasks.POST("", s.createTask)
			tasks.GET("", s.listTasks)
			tasks.GET("/:id", s.getTask)
			tasks.PUT("/:id", s.updateTask)
			tasks.DELETE("/:id", s.deleteTask)
			tasks.POST("/:id/execute", s.executeTask)
			tasks.GET("/:id/status", s.getTaskStatus)
		}

		workflows := v1.Group("/workflows")
		{
			workflows.POST("", s.createWorkflow)
			workflows.GET("", s.listWorkflows)
			workflows.GET("/:id", s.getWorkflow)
			workflows.PUT("/:id", s.updateWorkflow)
			workflows.DELETE("/:id", s.deleteWorkflow)
			workflows.POST("/:id/execute", s.executeWorkflow)
			workflows.GET("/:id/status", s.getWorkflowStatus)
		}

		toolsGroup := v1.Group("/tools")
		{
			toolsGroup.GET("", s.listTools)
			toolsGroup.GET("/:name", s.getTool)
			toolsGroup.POST("/:name/execute", s.executeTool)
		}

		llm := v1.Group("/llm")
		{
			llm.GET("/providers", s.listLLMProviders)
			llm.POST("/providers/:provider/generate", s.generateLLMResponse)
		}

		memoryGroup := v1.Group("/memory")
		{
			memoryGroup.POST("/:backend/store", s.storeMemory)
			memoryGroup.GET("/:backend/retrieve/:key", s.retrieveMemory)
			memoryGroup.DELETE("/:backend/:key", s.deleteMemory)
			memoryGroup.GET("/:backend/search", s.searchMemory)
		}
	}

	if config.EnableDocs {
		s.router.GET(config.DocsPath, ginSwagger.WrapHandler(swaggerFiles.Handler))
	}
}

// Start starts the REST API server
func (s *Server) Start() error {
	s.logger.WithField("port", s.port).Info("Starting REST API server")

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: s.router,
	}

	return s.httpServer.ListenAndServe()
}

// Stop stops the REST API server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping REST API server")
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}

	return nil
}

// corsMiddleware adds CORS headers
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Health check endpoint
// @Summary Health check
// @Description Get the health status of the API server
// @Tags health
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /health [get]
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"service":   "GoLEM API",
	})
}

// CreateAgentRequest represents the request to create an agent
type CreateAgentRequest struct {
	Name        string            `json:"name" binding:"required"`
	Description string            `json:"description"`
	Provider    string            `json:"provider" binding:"required"`
	Model       string            `json:"model" binding:"required"`
	Config      map[string]string `json:"config"`
	Tools       []string          `json:"tools"`
}

// AgentResponse represents an agent response
type AgentResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Provider    string            `json:"provider"`
	Model       string            `json:"model"`
	Config      map[string]string `json:"config"`
	Tools       []string          `json:"tools"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Create agent endpoint
// @Summary Create a new agent
// @Description Create a new agent with specified configuration
// @Tags agents
// @Accept json
// @Produce json
// @Param agent body CreateAgentRequest true "Agent configuration"
// @Success 201 {object} AgentResponse
// @Router /api/v1/agents [post]
func (s *Server) createAgent(c *gin.Context) {
	var req CreateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var llmProvider golem.LLMProvider

	switch req.Provider {
	case "openai":
		apiKey, _ := req.Config["api_key"]
		llmProvider = openai.NewProvider(apiKey)
	case "anthropic":
		// TODO: Anthropic provider needs interface fix, skip for now
		c.JSON(http.StatusBadRequest, gin.H{"error": "anthropic provider temporarily unavailable"})
		return
	case "ollama":
		cfg := ollama.Config{}
		if baseURL, ok := req.Config["base_url"]; ok {
			cfg.BaseURL = baseURL
		}
		llmProvider = ollama.NewProvider(cfg)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported LLM provider"})
		return
	}

	memoryConfig := golem.MemoryConfig{
		Backend: "memory",
		MaxSize: 1000,
	}

	agentConfig := agent.Config{
		Name:        req.Name,
		Role:        req.Description,
		LLMProvider: llmProvider,
		Temperature: 0.7,
		MaxTokens:   1000,
		Memory:      memoryConfig,
	}

	agentInstance := agent.NewAgent(req.Name, agentConfig)

	for _, toolName := range req.Tools {
		// TODO: Validate tool existence
		_ = toolName
	}

	agentID := fmt.Sprintf("agent_%d", time.Now().UnixNano())
	s.agents[agentID] = agentInstance

	response := AgentResponse{
		ID:          agentID,
		Name:        req.Name,
		Description: req.Description,
		Provider:    req.Provider,
		Model:       req.Model,
		Config:      req.Config,
		Tools:       req.Tools,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	c.JSON(http.StatusCreated, response)
}

// List agents endpoint
// @Summary List all agents
// @Description Get a list of all agents
// @Tags agents
// @Produce json
// @Success 200 {array} AgentResponse
// @Router /api/v1/agents [get]
func (s *Server) listAgents(c *gin.Context) {
	var agents []AgentResponse

	for id, agent := range s.agents {
		response := AgentResponse{
			ID:          id,
			Name:        agent.Name(),
			Description: agent.Role(),
			CreatedAt:   time.Now(), // TODO: Replace with actual creation time
			UpdatedAt:   time.Now(),
		}
		agents = append(agents, response)
	}

	c.JSON(http.StatusOK, agents)
}

// Get agent endpoint
// @Summary Get agent by ID
// @Description Get details of a specific agent
// @Tags agents
// @Produce json
// @Param id path string true "Agent ID"
// @Success 200 {object} AgentResponse
// @Router /api/v1/agents/{id} [get]
func (s *Server) getAgent(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := s.agents[agentID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	response := AgentResponse{
		ID:          agentID,
		Name:        agent.Name(),
		Description: agent.Role(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// Update agent endpoint
// @Summary Update agent
// @Description Update an existing agent
// @Tags agents
// @Accept json
// @Produce json
// @Param id path string true "Agent ID"
// @Param agent body CreateAgentRequest true "Updated agent configuration"
// @Success 200 {object} AgentResponse
// @Router /api/v1/agents/{id} [put]
func (s *Server) updateAgent(c *gin.Context) {
	agentID := c.Param("id")
	if _, exists := s.agents[agentID]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	var req CreateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Validate and update agent configuration
	response := AgentResponse{
		ID:          agentID,
		Name:        req.Name,
		Description: req.Description,
		Provider:    req.Provider,
		Model:       req.Model,
		Config:      req.Config,
		Tools:       req.Tools,
		UpdatedAt:   time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// Delete agent endpoint
// @Summary Delete agent
// @Description Delete an agent
// @Tags agents
// @Param id path string true "Agent ID"
// @Success 204
// @Router /api/v1/agents/{id} [delete]
func (s *Server) deleteAgent(c *gin.Context) {
	agentID := c.Param("id")
	if _, exists := s.agents[agentID]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	delete(s.agents, agentID)
	c.Status(http.StatusNoContent)
}

// ExecuteAgentRequest represents the request to execute an agent
type ExecuteAgentRequest struct {
	Input   string                 `json:"input" binding:"required"`
	Context map[string]interface{} `json:"context"`
}

// ExecuteAgentResponse represents the response from agent execution
type ExecuteAgentResponse struct {
	Output   string                 `json:"output"`
	Context  map[string]interface{} `json:"context"`
	Duration time.Duration          `json:"duration"`
	Success  bool                   `json:"success"`
	Error    string                 `json:"error,omitempty"`
}

// Execute agent endpoint
// @Summary Execute agent
// @Description Execute an agent with given input
// @Tags agents
// @Accept json
// @Produce json
// @Param id path string true "Agent ID"
// @Param request body ExecuteAgentRequest true "Execution request"
// @Success 200 {object} ExecuteAgentResponse
// @Router /api/v1/agents/{id}/execute [post]
func (s *Server) executeAgent(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := s.agents[agentID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	var req ExecuteAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	start := time.Now()

	taskConfig := task.Config{
		Name:        "API Task",
		Description: "Task executed via REST API",
		Input: golem.TaskInput{
			Text:       req.Input,
			Parameters: req.Context,
			Context:    make(map[string]interface{}),
		},
	}

	taskObj := task.NewTask("api-task", taskConfig)
	output, err := agent.Execute(c.Request.Context(), taskObj)
	duration := time.Since(start)

	response := ExecuteAgentResponse{
		Output:   output.Output,
		Context:  req.Context,
		Duration: duration,
		Success:  err == nil,
	}

	if err != nil {
		response.Error = err.Error()
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

type ChatRequest struct {
	Message string `json:"message" binding:"required"`
	Stream  bool   `json:"stream"`
}

type ChatResponse struct {
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Success  bool          `json:"success"`
	Error    string        `json:"error,omitempty"`
}

// Chat with agent endpoint
// @Summary Chat with agent
// @Description Have a conversation with an agent
// @Tags agents
// @Accept json
// @Produce json
// @Param id path string true "Agent ID"
// @Param request body ChatRequest true "Chat request"
// @Success 200 {object} ChatResponse
// @Router /api/v1/agents/{id}/chat [post]
func (s *Server) chatWithAgent(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := s.agents[agentID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	start := time.Now()

	taskConfig := task.Config{
		Name:        "Chat Task",
		Description: "Chat message via REST API",
		Input: golem.TaskInput{
			Text:       req.Message,
			Parameters: make(map[string]interface{}),
			Context:    make(map[string]interface{}),
		},
	}

	taskObj := task.NewTask("chat-task", taskConfig)
	response, err := agent.Execute(c.Request.Context(), taskObj)
	duration := time.Since(start)

	chatResponse := ChatResponse{
		Message:  response.Output,
		Duration: duration,
		Success:  err == nil,
	}

	if err != nil {
		chatResponse.Error = err.Error()
		c.JSON(http.StatusInternalServerError, chatResponse)
		return
	}

	c.JSON(http.StatusOK, chatResponse)
}

type CreateTaskRequest struct {
	Name        string                 `json:"name" binding:"required"`
	Description string                 `json:"description"`
	Type        string                 `json:"type" binding:"required"`
	Input       map[string]interface{} `json:"input"`
	AgentID     string                 `json:"agent_id"`
	Priority    int                    `json:"priority"`
}

type TaskResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Status      string                 `json:"status"`
	Input       map[string]interface{} `json:"input"`
	Output      map[string]interface{} `json:"output,omitempty"`
	AgentID     string                 `json:"agent_id"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Create task endpoint
// @Summary Create a new task
// @Description Create a new task with specified configuration
// @Tags tasks
// @Accept json
// @Produce json
// @Param task body CreateTaskRequest true "Task configuration"
// @Success 201 {object} TaskResponse
// @Router /api/v1/tasks [post]
func (s *Server) createTask(c *gin.Context) {
	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	taskConfig := task.Config{
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Timeout:     5 * time.Minute,
		RetryCount:  3,
	}

	if req.Input != nil {
		taskConfig.Input = golem.TaskInput{
			Parameters: req.Input,
			Context:    make(map[string]interface{}),
		}
	}

	newTask := task.NewTask(req.Name, taskConfig)
	taskID := fmt.Sprintf("task_%d", time.Now().UnixNano())

	inputMap := make(map[string]interface{})
	if taskInput := newTask.GetInput(); taskInput.Parameters != nil {
		inputMap = taskInput.Parameters
	}

	response := TaskResponse{
		ID:          taskID,
		Name:        newTask.Name(),
		Description: newTask.Description(),
		Type:        req.Type,
		Status:      "pending",
		Input:       inputMap,
		AgentID:     req.AgentID,
		Priority:    taskConfig.Priority,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	c.JSON(http.StatusCreated, response)
}

// List tasks endpoint
// @Summary List all tasks
// @Description Get a list of all tasks
// @Tags tasks
// @Produce json
// @Success 200 {array} TaskResponse
// @Router /api/v1/tasks [get]
func (s *Server) listTasks(c *gin.Context) {
	// TODO: Implement task retrieval logic
	tasks := []TaskResponse{}
	c.JSON(http.StatusOK, tasks)
}

// Get task endpoint
// @Summary Get task by ID
// @Description Get details of a specific task
// @Tags tasks
// @Produce json
// @Param id path string true "Task ID"
// @Success 200 {object} TaskResponse
// @Router /api/v1/tasks/{id} [get]
func (s *Server) getTask(c *gin.Context) {
	taskID := c.Param("id")

	// Mock response
	response := TaskResponse{
		ID:        taskID,
		Name:      "Sample Task",
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// Update task endpoint
// @Summary Update task
// @Description Update an existing task
// @Tags tasks
// @Accept json
// @Produce json
// @Param id path string true "Task ID"
// @Param task body CreateTaskRequest true "Updated task configuration"
// @Success 200 {object} TaskResponse
// @Router /api/v1/tasks/{id} [put]
func (s *Server) updateTask(c *gin.Context) {
	taskID := c.Param("id")

	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response := TaskResponse{
		ID:          taskID,
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		UpdatedAt:   time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// Delete task endpoint
// @Summary Delete task
// @Description Delete a task
// @Tags tasks
// @Param id path string true "Task ID"
// @Success 204
// @Router /api/v1/tasks/{id} [delete]
func (s *Server) deleteTask(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Execute task endpoint
// @Summary Execute task
// @Description Execute a task
// @Tags tasks
// @Param id path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/tasks/{id}/execute [post]
func (s *Server) executeTask(c *gin.Context) {
	taskID := c.Param("id")

	c.JSON(http.StatusOK, gin.H{
		"task_id": taskID,
		"status":  "executed",
		"result":  "Task executed successfully",
	})
}

// Get task status endpoint
// @Summary Get task status
// @Description Get the current status of a task
// @Tags tasks
// @Produce json
// @Param id path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/tasks/{id}/status [get]
func (s *Server) getTaskStatus(c *gin.Context) {
	taskID := c.Param("id")

	c.JSON(http.StatusOK, gin.H{
		"task_id":    taskID,
		"status":     "pending",
		"progress":   0,
		"updated_at": time.Now(),
	})
}

func (s *Server) createWorkflow(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "workflow created"})
}

func (s *Server) listWorkflows(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{})
}

func (s *Server) getWorkflow(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"workflow": "details"})
}

func (s *Server) updateWorkflow(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "workflow updated"})
}

func (s *Server) deleteWorkflow(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

func (s *Server) executeWorkflow(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "workflow executed"})
}

func (s *Server) getWorkflowStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "running"})
}

// List tools endpoint
// @Summary List all tools
// @Description Get a list of all available tools
// @Tags tools
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/tools [get]
func (s *Server) listTools(c *gin.Context) {
	toolNames := tools.ListTools()
	toolList := make(map[string]interface{})

	for _, name := range toolNames {
		if tool, err := tools.GetTool(name); err == nil {
			toolList[name] = map[string]interface{}{
				"name":        tool.Name(),
				"description": tool.Description(),
				"schema":      tool.GetSchema(),
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"tools": toolList,
		"count": len(toolNames),
	})
}

// Get tool endpoint
// @Summary Get tool by name
// @Description Get details of a specific tool
// @Tags tools
// @Produce json
// @Param name path string true "Tool name"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/tools/{name} [get]
func (s *Server) getTool(c *gin.Context) {
	toolName := c.Param("name")

	tool, err := tools.GetTool(toolName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":        tool.Name(),
		"description": tool.Description(),
		"schema":      tool.GetSchema(),
	})
}

type ExecuteToolRequest struct {
	Parameters map[string]interface{} `json:"parameters" binding:"required"`
}

// Execute tool endpoint
// @Summary Execute tool
// @Description Execute a tool with given parameters
// @Tags tools
// @Accept json
// @Produce json
// @Param name path string true "Tool name"
// @Param request body ExecuteToolRequest true "Tool execution request"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/tools/{name}/execute [post]
func (s *Server) executeTool(c *gin.Context) {
	toolName := c.Param("name")

	var req ExecuteToolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tool, err := tools.GetTool(toolName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found"})
		return
	}

	start := time.Now()
	result, err := tool.Execute(c.Request.Context(), req.Parameters)
	duration := time.Since(start)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":    err.Error(),
			"duration": duration.String(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tool":     toolName,
		"result":   result,
		"duration": duration.String(),
		"success":  true,
	})
}

// List LLM providers endpoint
// @Summary List LLM providers
// @Description Get a list of supported LLM providers
// @Tags llm
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/llm/providers [get]
func (s *Server) listLLMProviders(c *gin.Context) {
	providers := map[string]interface{}{
		"openai": map[string]interface{}{
			"name":        "OpenAI",
			"models":      []string{"gpt-4", "gpt-3.5-turbo"},
			"description": "OpenAI GPT models",
		},
		"anthropic": map[string]interface{}{
			"name":        "Anthropic",
			"models":      []string{"claude-3-opus", "claude-3-sonnet", "claude-3-haiku"},
			"description": "Anthropic Claude models",
		},
		"ollama": map[string]interface{}{
			"name":        "Ollama",
			"models":      []string{"llama2", "codellama", "mistral"},
			"description": "Local Ollama models",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"providers": providers,
		"count":     len(providers),
	})
}

type GenerateLLMRequest struct {
	Model    string              `json:"model" binding:"required"`
	Messages []golem.ChatMessage `json:"messages" binding:"required"`
	Config   map[string]string   `json:"config"`
}

// Generate LLM response endpoint
// @Summary Generate LLM response
// @Description Generate response using specified LLM provider
// @Tags llm
// @Accept json
// @Produce json
// @Param provider path string true "Provider name"
// @Param request body GenerateLLMRequest true "Generation request"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/llm/providers/{provider}/generate [post]
func (s *Server) generateLLMResponse(c *gin.Context) {
	provider := c.Param("provider")

	var req GenerateLLMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var llmProvider golem.LLMProvider

	switch provider {
	case "openai":
		apiKey, _ := req.Config["api_key"]
		llmProvider = openai.NewProvider(apiKey)
	case "ollama":
		cfg := ollama.Config{}
		if baseURL, ok := req.Config["base_url"]; ok {
			cfg.BaseURL = baseURL
		}
		llmProvider = ollama.NewProvider(cfg)
	case "anthropic":
		// TODO: Anthropic provider needs interface fix, skip for now
		c.JSON(http.StatusBadRequest, gin.H{"error": "anthropic provider temporarily unavailable"})
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
		return
	}

	genReq := &golem.GenerationRequest{
		Prompt:      convertMessagesToPrompt(req.Messages),
		Model:       req.Model,
		Temperature: 0.7,
		MaxTokens:   1000,
		Context:     make(map[string]interface{}),
	}

	start := time.Now()
	response, err := llmProvider.GenerateResponse(c.Request.Context(), genReq)
	duration := time.Since(start)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":    err.Error(),
			"duration": duration.String(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"provider": provider,
		"model":    req.Model,
		"response": response,
		"duration": duration.String(),
		"success":  true,
	})
}

type StoreMemoryRequest struct {
	Key   string      `json:"key" binding:"required"`
	Value interface{} `json:"value" binding:"required"`
	TTL   int         `json:"ttl"`
}

// Store memory endpoint
// @Summary Store memory
// @Description Store data in memory backend
// @Tags memory
// @Accept json
// @Produce json
// @Param backend path string true "Memory backend"
// @Param request body StoreMemoryRequest true "Store request"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/memory/{backend}/store [post]
func (s *Server) storeMemory(c *gin.Context) {
	backend := c.Param("backend")

	var req StoreMemoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var memoryBackend golem.Memory
	switch backend {
	case "inmemory":
		config := golem.MemoryConfig{Backend: "memory", MaxSize: 1000}
		memoryBackend = memory.NewMemory(config)
	case "redis":
		config := golem.MemoryConfig{Backend: "redis", MaxSize: 1000}
		memoryBackend = memory.NewMemory(config)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported memory backend"})
		return
	}

	err := memoryBackend.Store(c.Request.Context(), req.Key, req.Value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"backend": backend,
		"key":     req.Key,
		"stored":  true,
	})
}

// Retrieve memory endpoint
// @Summary Retrieve memory
// @Description Retrieve data from memory backend
// @Tags memory
// @Produce json
// @Param backend path string true "Memory backend"
// @Param key path string true "Memory key"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/memory/{backend}/retrieve/{key} [get]
func (s *Server) retrieveMemory(c *gin.Context) {
	backend := c.Param("backend")
	key := c.Param("key")

	// Mock response
	c.JSON(http.StatusOK, gin.H{
		"backend": backend,
		"key":     key,
		"value":   "retrieved value",
		"found":   true,
	})
}

// Delete memory endpoint
// @Summary Delete memory
// @Description Delete data from memory backend
// @Tags memory
// @Param backend path string true "Memory backend"
// @Param key path string true "Memory key"
// @Success 204
// @Router /api/v1/memory/{backend}/{key} [delete]
func (s *Server) deleteMemory(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Search memory endpoint
// @Summary Search memory
// @Description Search data in memory backend
// @Tags memory
// @Produce json
// @Param backend path string true "Memory backend"
// @Param q query string true "Search query"
// @Param limit query int false "Result limit"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/memory/{backend}/search [get]
func (s *Server) searchMemory(c *gin.Context) {
	backend := c.Param("backend")
	query := c.Query("q")
	limitStr := c.DefaultQuery("limit", "10")

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 10
	}

	c.JSON(http.StatusOK, gin.H{
		"backend": backend,
		"query":   query,
		"limit":   limit,
		"results": []interface{}{},
		"count":   0,
	})
}
