// Package golem provides the main engine implementation for the Go Language Execution Model.
package golem

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type engine struct {
	agents     map[string]Agent
	workflows  map[string]Workflow
	eventBus   EventBus
	config     EngineConfig
	logger     *logrus.Logger
	metrics    EngineMetrics
	running    bool
	shutdown   chan struct{}
	mu         sync.RWMutex
	taskQueue  chan TaskExecutionRequest
	workers    int
	workerPool sync.WaitGroup
}

type EngineConfig struct {
	MaxConcurrentTasks int           `json:"max_concurrent_tasks" yaml:"max_concurrent_tasks"`
	DefaultTimeout     time.Duration `json:"default_timeout" yaml:"default_timeout"`
	WorkerPoolSize     int           `json:"worker_pool_size" yaml:"worker_pool_size"`
	EnableMetrics      bool          `json:"enable_metrics" yaml:"enable_metrics"`
	LogLevel           string        `json:"log_level" yaml:"log_level"`
}

type TaskExecutionRequest struct {
	Task     Task
	Context  context.Context
	Response chan TaskExecutionResponse
}

type TaskExecutionResponse struct {
	Result *TaskResult
	Error  error
}

type basicWorkflow struct {
	id     string
	name   string
	config WorkflowConfig
	logger *logrus.Logger
	tasks  []Task
	status WorkflowStatus
}

// ID returns the workflow ID
func (w *basicWorkflow) ID() string {
	return w.id
}

// Name returns the workflow name
func (w *basicWorkflow) Name() string {
	return w.name
}

// AddTask adds a task to the workflow
func (w *basicWorkflow) AddTask(task Task) error {
	w.tasks = append(w.tasks, task)
	return nil
}

// RemoveTask removes a task from the workflow
func (w *basicWorkflow) RemoveTask(taskID string) error {
	for i, task := range w.tasks {
		if task.ID() == taskID {
			w.tasks = append(w.tasks[:i], w.tasks[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("task with ID %s not found", taskID)
}

// Execute executes the workflow (stub implementation)
func (w *basicWorkflow) Execute(ctx context.Context) (*WorkflowResult, error) {
	w.logger.WithFields(logrus.Fields{
		"workflow_id":   w.id,
		"workflow_name": w.name,
	}).Info("Executing basic workflow")

	w.status = WorkflowStatusRunning
	start := time.Now()

	// TODO: Implement actual task execution logic
	taskResults := make([]TaskResult, 0, len(w.tasks))
	for _, task := range w.tasks {
		// TODO: Replace with actual task execution logic
		result := TaskResult{
			ID:        NewUUID(),
			TaskID:    task.ID(),
			AgentID:   "",
			Output:    "Task completed successfully",
			Metadata:  make(map[string]interface{}),
			Duration:  time.Millisecond * 10,
			Success:   true,
			CreatedAt: time.Now(),
		}
		taskResults = append(taskResults, result)
	}

	w.status = WorkflowStatusCompleted
	duration := time.Since(start)

	return &WorkflowResult{
		ID:          NewUUID(),
		WorkflowID:  w.id,
		TaskResults: taskResults,
		Status:      w.status,
		Duration:    duration,
		Metadata:    make(map[string]interface{}),
		CreatedAt:   start,
	}, nil
}

// GetStatus returns the workflow status
func (w *basicWorkflow) GetStatus() WorkflowStatus {
	return w.status
}

// GetTasks returns all tasks in the workflow
func (w *basicWorkflow) GetTasks() []Task {
	return w.tasks
}

// GetDAG returns the dependency graph of tasks
func (w *basicWorkflow) GetDAG() *DAG {
	// TODO: Implement actual DAG generation logic
	return &DAG{
		Nodes: make([]DAGNode, 0),
		Edges: make([]DAGEdge, 0),
	}
}

// Validate checks if the workflow is valid
func (w *basicWorkflow) Validate() error {
	if w.id == "" {
		return fmt.Errorf("workflow ID cannot be empty")
	}
	if w.name == "" {
		return fmt.Errorf("workflow name cannot be empty")
	}
	return nil
}

// NewEngine creates a new GoLEM engine with the given configuration
func NewEngine(config ...EngineConfig) Engine {
	var cfg EngineConfig
	if len(config) > 0 {
		cfg = config[0]
	} else {
		cfg = DefaultEngineConfig()
	}

	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	eng := &engine{
		agents:    make(map[string]Agent),
		workflows: make(map[string]Workflow),
		eventBus:  NewEventBus(),
		config:    cfg,
		logger:    logger,
		metrics:   EngineMetrics{},
		shutdown:  make(chan struct{}),
		taskQueue: make(chan TaskExecutionRequest, cfg.MaxConcurrentTasks),
		workers:   cfg.WorkerPoolSize,
	}

	eng.startWorkers()
	eng.running = true

	logger.WithFields(logrus.Fields{
		"max_concurrent_tasks": cfg.MaxConcurrentTasks,
		"worker_pool_size":     cfg.WorkerPoolSize,
		"default_timeout":      cfg.DefaultTimeout,
	}).Info("GoLEM engine started")

	return eng
}

// DefaultEngineConfig returns the default engine configuration
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		MaxConcurrentTasks: 10,
		DefaultTimeout:     30 * time.Minute,
		WorkerPoolSize:     5,
		EnableMetrics:      true,
		LogLevel:           "info",
	}
}

// RegisterAgent adds an agent to the engine
func (e *engine) RegisterAgent(agent Agent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.agents[agent.ID()]; exists {
		return fmt.Errorf("agent with ID %s already exists", agent.ID())
	}

	e.agents[agent.ID()] = agent
	e.metrics.ActiveAgents = len(e.agents)

	e.logger.WithFields(logrus.Fields{
		"agent_id":   agent.ID(),
		"agent_name": agent.Name(),
		"agent_role": agent.Role(),
	}).Info("Agent registered")

	event := Event{
		ID:     NewUUID(),
		Type:   EventTypeAgentRegistered,
		Source: "engine",
		Data: map[string]interface{}{
			"agent_id":   agent.ID(),
			"agent_name": agent.Name(),
			"agent_role": agent.Role(),
		},
		Timestamp: time.Now(),
	}
	e.eventBus.Publish(event)

	return nil
}

// UnregisterAgent removes an agent from the engine
func (e *engine) UnregisterAgent(agentID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	agent, exists := e.agents[agentID]
	if !exists {
		return fmt.Errorf("agent with ID %s not found", agentID)
	}

	delete(e.agents, agentID)
	e.metrics.ActiveAgents = len(e.agents)

	e.logger.WithFields(logrus.Fields{
		"agent_id":   agentID,
		"agent_name": agent.Name(),
	}).Info("Agent unregistered")

	// Publish event
	event := Event{
		ID:     NewUUID(),
		Type:   EventTypeAgentUnregistered,
		Source: "engine",
		Data: map[string]interface{}{
			"agent_id":   agentID,
			"agent_name": agent.Name(),
		},
		Timestamp: time.Now(),
	}
	e.eventBus.Publish(event)

	return nil
}

// GetAgent retrieves an agent by ID
func (e *engine) GetAgent(agentID string) (Agent, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	agent, exists := e.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent with ID %s not found", agentID)
	}

	return agent, nil
}

// ListAgents returns all registered agents
func (e *engine) ListAgents() []Agent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	agents := make([]Agent, 0, len(e.agents))
	for _, agent := range e.agents {
		agents = append(agents, agent)
	}

	return agents
}

// CreateWorkflow creates a new workflow and registers it with the engine
func (e *engine) CreateWorkflow(name string, config WorkflowConfig) Workflow {
	id := NewUUID()

	// TODO: Implement actual workflow creation logic
	workflow := &basicWorkflow{
		id:     id,
		name:   name,
		config: config,
		logger: e.logger,
	}

	e.mu.Lock()
	e.workflows[workflow.ID()] = workflow
	e.mu.Unlock()

	e.logger.WithFields(logrus.Fields{
		"workflow_id":     workflow.ID(),
		"workflow_name":   name,
		"max_concurrency": config.MaxConcurrency,
	}).Info("Workflow created")

	return workflow
}

// RegisterWorkflow registers an existing workflow with the engine
func (e *engine) RegisterWorkflow(workflow Workflow) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.workflows[workflow.ID()]; exists {
		return fmt.Errorf("workflow with ID %s already exists", workflow.ID())
	}

	e.workflows[workflow.ID()] = workflow

	e.logger.WithFields(logrus.Fields{
		"workflow_id":   workflow.ID(),
		"workflow_name": workflow.Name(),
	}).Info("Workflow registered")

	return nil
}

// ExecuteTask executes a single task
func (e *engine) ExecuteTask(ctx context.Context, task Task) (*TaskResult, error) {
	if !e.running {
		return nil, fmt.Errorf("engine is not running")
	}

	task.SetStatus(TaskStatusRunning)
	agentID := task.GetConfig().CustomConfig["agent_id"]
	if agentID == nil {
		return nil, fmt.Errorf("no agent assigned to task %s", task.ID())
	}

	agent, err := e.GetAgent(agentID.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get agent %s: %w", agentID, err)
	}

	if !agent.IsHealthy(ctx) {
		return nil, fmt.Errorf("agent %s is not healthy", agent.ID())
	}

	request := TaskExecutionRequest{
		Task:     task,
		Context:  ctx,
		Response: make(chan TaskExecutionResponse, 1),
	}

	select {
	case e.taskQueue <- request:
		// TODO: Handle task queued successfully
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.shutdown:
		return nil, fmt.Errorf("engine is shutting down")
	}

	select {
	case response := <-request.Response:
		if response.Error != nil {
			task.SetStatus(TaskStatusFailed)
			e.metrics.FailedTasks++
			return response.Result, response.Error
		}

		task.SetStatus(TaskStatusCompleted)
		task.SetResult(response.Result)
		e.metrics.CompletedTasks++
		return response.Result, nil

	case <-ctx.Done():
		task.SetStatus(TaskStatusCancelled)
		return nil, ctx.Err()

	case <-e.shutdown:
		task.SetStatus(TaskStatusCancelled)
		return nil, fmt.Errorf("engine is shutting down")
	}
}

// ExecuteWorkflow executes a workflow
func (e *engine) ExecuteWorkflow(ctx context.Context, workflow Workflow) (*WorkflowResult, error) {
	if !e.running {
		return nil, fmt.Errorf("engine is not running")
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id":   workflow.ID(),
		"workflow_name": workflow.Name(),
	}).Info("Starting workflow execution")

	event := Event{
		ID:     NewUUID(),
		Type:   EventTypeWorkflowStarted,
		Source: "engine",
		Data: map[string]interface{}{
			"workflow_id":   workflow.ID(),
			"workflow_name": workflow.Name(),
		},
		Timestamp: time.Now(),
	}
	e.eventBus.Publish(event)

	result, err := workflow.Execute(ctx)
	if err != nil {
		e.logger.WithError(err).WithFields(logrus.Fields{
			"workflow_id": workflow.ID(),
		}).Error("Workflow execution failed")

		failEvent := Event{
			ID:     NewUUID(),
			Type:   EventTypeWorkflowFailed,
			Source: "engine",
			Data: map[string]interface{}{
				"workflow_id": workflow.ID(),
				"error":       err.Error(),
			},
			Timestamp: time.Now(),
		}
		e.eventBus.Publish(failEvent)

		return result, err
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id":     workflow.ID(),
		"duration":        result.Duration,
		"completed_tasks": len(result.TaskResults),
	}).Info("Workflow execution completed")

	completeEvent := Event{
		ID:     NewUUID(),
		Type:   EventTypeWorkflowCompleted,
		Source: "engine",
		Data: map[string]interface{}{
			"workflow_id":     workflow.ID(),
			"duration":        result.Duration,
			"completed_tasks": len(result.TaskResults),
		},
		Timestamp: time.Now(),
	}
	e.eventBus.Publish(completeEvent)

	return result, nil
}

// GetMetrics returns engine performance metrics
func (e *engine) GetMetrics() EngineMetrics {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.metrics
}

// IsHealthy checks if the engine is healthy
func (e *engine) IsHealthy() bool {
	return e.running
}

// Shutdown gracefully shuts down the engine
func (e *engine) Shutdown(ctx context.Context) error {
	e.logger.Info("Shutting down GoLEM engine")

	e.mu.Lock()
	e.running = false
	e.mu.Unlock()
	close(e.shutdown)
	done := make(chan struct{})
	go func() {
		e.workerPool.Wait()
		close(done)
	}()

	select {
	case <-done:
		e.logger.Info("All workers shut down successfully")
	case <-ctx.Done():
		e.logger.Warn("Shutdown timeout reached, forcing shutdown")
		return ctx.Err()
	}

	if e.eventBus != nil {
		if err := e.eventBus.Close(); err != nil {
			e.logger.WithError(err).Warn("Failed to close event bus")
		}
	}

	e.logger.Info("GoLEM engine shut down completed")
	return nil
}

// startWorkers starts the worker pool for task execution
func (e *engine) startWorkers() {
	for i := 0; i < e.workers; i++ {
		e.workerPool.Add(1)
		go e.worker(i)
	}
}

// worker is the worker goroutine that processes tasks
func (e *engine) worker(id int) {
	defer e.workerPool.Done()

	logger := e.logger.WithField("worker_id", id)
	logger.Info("Worker started")

	for {
		select {
		case request := <-e.taskQueue:
			logger.WithField("task_id", request.Task.ID()).Debug("Processing task")

			start := time.Now()
			result, err := e.executeTaskInternal(request.Context, request.Task)
			duration := time.Since(start)

			e.mu.Lock()
			if e.metrics.AverageLatency == 0 {
				e.metrics.AverageLatency = duration
			} else {
				e.metrics.AverageLatency = (e.metrics.AverageLatency + duration) / 2
			}
			if result != nil {
				e.metrics.TokensUsed += int64(result.TokensUsed)
			}
			e.mu.Unlock()

			response := TaskExecutionResponse{
				Result: result,
				Error:  err,
			}

			select {
			case request.Response <- response:
				// TODO: Handle response sent
			case <-request.Context.Done():
				// TODO: Handle context cancellation
				logger.WithField("task_id", request.Task.ID()).Warn("Request context cancelled before response could be sent")
			}

		case <-e.shutdown:
			logger.Info("Worker shutting down")
			return
		}
	}
}

// executeTaskInternal executes a task internally
func (e *engine) executeTaskInternal(ctx context.Context, task Task) (*TaskResult, error) {
	agentID := task.GetConfig().CustomConfig["agent_id"]
	if agentID == nil {
		return nil, fmt.Errorf("no agent assigned to task %s", task.ID())
	}

	agent, err := e.GetAgent(agentID.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get agent %s: %w", agentID, err)
	}

	event := Event{
		ID:     NewUUID(),
		Type:   EventTypeTaskStarted,
		Source: "engine",
		Data: map[string]interface{}{
			"task_id":    task.ID(),
			"agent_id":   agent.ID(),
			"task_name":  task.Name(),
			"agent_name": agent.Name(),
		},
		Timestamp: time.Now(),
	}
	e.eventBus.Publish(event)

	result, err := agent.Execute(ctx, task)

	if err != nil {
		failEvent := Event{
			ID:     NewUUID(),
			Type:   EventTypeTaskFailed,
			Source: "engine",
			Data: map[string]interface{}{
				"task_id":  task.ID(),
				"agent_id": agent.ID(),
				"error":    err.Error(),
			},
			Timestamp: time.Now(),
		}
		e.eventBus.Publish(failEvent)

		return result, err
	}

	completeEvent := Event{
		ID:     NewUUID(),
		Type:   EventTypeTaskCompleted,
		Source: "engine",
		Data: map[string]interface{}{
			"task_id":     task.ID(),
			"agent_id":    agent.ID(),
			"duration":    result.Duration,
			"tokens_used": result.TokensUsed,
		},
		Timestamp: time.Now(),
	}
	e.eventBus.Publish(completeEvent)

	return result, nil
}
