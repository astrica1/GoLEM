// Package workflow provides workflow orchestration for the Go Language Execution Model.
package workflow

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type workflow struct {
	id           string
	name         string
	config       golem.WorkflowConfig
	tasks        map[string]golem.Task
	dag          *golem.DAG
	status       golem.WorkflowStatus
	eventBus     golem.EventBus
	logger       *logrus.Logger
	createdAt    time.Time
	updatedAt    time.Time
	mu           sync.RWMutex
	taskExecutor TaskExecutor
}

type TaskExecutor interface {
	ExecuteTask(ctx context.Context, task golem.Task) (*golem.TaskResult, error)
}

// NewWorkflow creates a new workflow with the given configuration
func NewWorkflow(name string, config golem.WorkflowConfig, eventBus golem.EventBus, logger *logrus.Logger) golem.Workflow {
	if logger == nil {
		logger = logrus.New()
	}

	return &workflow{
		id:        uuid.New().String(),
		name:      name,
		config:    config,
		tasks:     make(map[string]golem.Task),
		dag:       &golem.DAG{Nodes: []golem.DAGNode{}, Edges: []golem.DAGEdge{}},
		status:    golem.WorkflowStatusPending,
		eventBus:  eventBus,
		logger:    logger,
		createdAt: time.Now(),
		updatedAt: time.Now(),
	}
}

// ID returns the workflow identifier
func (w *workflow) ID() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.id
}

// Name returns the workflow name
func (w *workflow) Name() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.name
}

// AddTask adds a task to the workflow
func (w *workflow) AddTask(task golem.Task) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.tasks[task.ID()]; exists {
		return fmt.Errorf("task with ID %s already exists in workflow", task.ID())
	}

	w.tasks[task.ID()] = task
	w.updatedAt = time.Now()

	node := golem.DAGNode{
		ID:     task.ID(),
		TaskID: task.ID(),
		Metadata: map[string]string{
			"name":        task.Name(),
			"description": task.Description(),
		},
	}
	w.dag.Nodes = append(w.dag.Nodes, node)

	for _, depID := range task.GetDependencies() {
		edge := golem.DAGEdge{
			From: depID,
			To:   task.ID(),
		}
		w.dag.Edges = append(w.dag.Edges, edge)
	}

	w.logger.WithFields(logrus.Fields{
		"workflow_id": w.id,
		"task_id":     task.ID(),
		"task_name":   task.Name(),
	}).Debug("Task added to workflow")

	return nil
}

// RemoveTask removes a task from the workflow
func (w *workflow) RemoveTask(taskID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.tasks[taskID]; !exists {
		return fmt.Errorf("task with ID %s not found in workflow", taskID)
	}

	delete(w.tasks, taskID)
	w.updatedAt = time.Now()

	for i, node := range w.dag.Nodes {
		if node.TaskID == taskID {
			w.dag.Nodes = append(w.dag.Nodes[:i], w.dag.Nodes[i+1:]...)
			break
		}
	}

	var newEdges []golem.DAGEdge
	for _, edge := range w.dag.Edges {
		if edge.From != taskID && edge.To != taskID {
			newEdges = append(newEdges, edge)
		}
	}
	w.dag.Edges = newEdges

	w.logger.WithFields(logrus.Fields{
		"workflow_id": w.id,
		"task_id":     taskID,
	}).Debug("Task removed from workflow")

	return nil
}

// Execute runs the entire workflow
func (w *workflow) Execute(ctx context.Context) (*golem.WorkflowResult, error) {
	w.mu.Lock()
	if w.status != golem.WorkflowStatusPending {
		w.mu.Unlock()
		return nil, fmt.Errorf("workflow is not in pending status (current: %s)", w.status.String())
	}

	if w.taskExecutor == nil {
		w.mu.Unlock()
		return nil, fmt.Errorf("no task executor configured for workflow")
	}

	w.status = golem.WorkflowStatusRunning
	w.updatedAt = time.Now()
	taskExecutor := w.taskExecutor
	w.mu.Unlock()

	start := time.Now()

	w.logger.WithFields(logrus.Fields{
		"workflow_id":   w.id,
		"workflow_name": w.name,
		"task_count":    len(w.tasks),
	}).Info("Starting workflow execution")

	result := golem.NewWorkflowResult(w.id)

	if err := w.Validate(); err != nil {
		w.setStatus(golem.WorkflowStatusFailed)
		result.Status = golem.WorkflowStatusFailed
		result.Error = fmt.Sprintf("workflow validation failed: %v", err)
		result.Duration = time.Since(start)
		return result, err
	}

	executionOrder, err := w.getExecutionOrder()
	if err != nil {
		w.setStatus(golem.WorkflowStatusFailed)
		result.Status = golem.WorkflowStatusFailed
		result.Error = fmt.Sprintf("failed to determine execution order: %v", err)
		result.Duration = time.Since(start)
		return result, err
	}

	var executeErr error
	if w.config.MaxConcurrency <= 1 {
		executeErr = w.executeSequential(ctx, executionOrder, taskExecutor, result)
	} else {
		executeErr = w.executeConcurrent(ctx, executionOrder, taskExecutor, result)
	}

	result.Duration = time.Since(start)

	if executeErr != nil {
		w.setStatus(golem.WorkflowStatusFailed)
		result.Status = golem.WorkflowStatusFailed
		result.Error = executeErr.Error()

		w.logger.WithError(executeErr).WithFields(logrus.Fields{
			"workflow_id": w.id,
			"duration":    result.Duration,
		}).Error("Workflow execution failed")

		return result, executeErr
	}

	allSuccess := true
	for _, taskResult := range result.TaskResults {
		if !taskResult.Success {
			allSuccess = false
			break
		}
	}

	if allSuccess {
		w.setStatus(golem.WorkflowStatusCompleted)
		result.Status = golem.WorkflowStatusCompleted
	} else {
		w.setStatus(golem.WorkflowStatusPartiallyCompleted)
		result.Status = golem.WorkflowStatusPartiallyCompleted
	}

	w.logger.WithFields(logrus.Fields{
		"workflow_id":     w.id,
		"status":          result.Status.String(),
		"duration":        result.Duration,
		"completed_tasks": len(result.TaskResults),
	}).Info("Workflow execution completed")

	return result, nil
}

// GetStatus returns the current workflow status
func (w *workflow) GetStatus() golem.WorkflowStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.status
}

// GetTasks returns all tasks in the workflow
func (w *workflow) GetTasks() []golem.Task {
	w.mu.RLock()
	defer w.mu.RUnlock()

	tasks := make([]golem.Task, 0, len(w.tasks))
	for _, task := range w.tasks {
		tasks = append(tasks, task)
	}

	return tasks
}

// GetDAG returns the dependency graph of tasks
func (w *workflow) GetDAG() *golem.DAG {
	w.mu.RLock()
	defer w.mu.RUnlock()

	dagCopy := &golem.DAG{
		Nodes: make([]golem.DAGNode, len(w.dag.Nodes)),
		Edges: make([]golem.DAGEdge, len(w.dag.Edges)),
	}
	copy(dagCopy.Nodes, w.dag.Nodes)
	copy(dagCopy.Edges, w.dag.Edges)

	return dagCopy
}

// Validate checks if the workflow is valid
func (w *workflow) Validate() error {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.name == "" {
		return fmt.Errorf("workflow name is required")
	}

	if len(w.tasks) == 0 {
		return fmt.Errorf("workflow must contain at least one task")
	}

	for _, task := range w.tasks {
		for _, depID := range task.GetDependencies() {
			if _, exists := w.tasks[depID]; !exists {
				return fmt.Errorf("task %s depends on non-existent task %s", task.ID(), depID)
			}
		}
	}

	if w.hasCycles() {
		return fmt.Errorf("workflow contains circular dependencies")
	}

	return nil
}

// SetTaskExecutor sets the task executor for the workflow
func (w *workflow) SetTaskExecutor(executor TaskExecutor) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.taskExecutor = executor
}

// setStatus sets the workflow status (thread-safe)
func (w *workflow) setStatus(status golem.WorkflowStatus) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = status
	w.updatedAt = time.Now()
}

// hasCycles checks if the DAG has cycles using DFS
func (w *workflow) hasCycles() bool {
	adjList := make(map[string][]string)
	for _, edge := range w.dag.Edges {
		adjList[edge.From] = append(adjList[edge.From], edge.To)
	}

	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(string) bool
	dfs = func(node string) bool {
		if recStack[node] {
			return true
		}
		if visited[node] {
			return false
		}

		visited[node] = true
		recStack[node] = true

		for _, neighbor := range adjList[node] {
			if dfs(neighbor) {
				return true
			}
		}

		recStack[node] = false
		return false
	}

	for _, node := range w.dag.Nodes {
		if !visited[node.TaskID] {
			if dfs(node.TaskID) {
				return true
			}
		}
	}

	return false
}

// getExecutionOrder returns the topological order of tasks
func (w *workflow) getExecutionOrder() ([][]string, error) {
	adjList := make(map[string][]string)
	inDegree := make(map[string]int)

	for _, node := range w.dag.Nodes {
		inDegree[node.TaskID] = 0
	}

	for _, edge := range w.dag.Edges {
		adjList[edge.From] = append(adjList[edge.From], edge.To)
		inDegree[edge.To]++
	}

	var levels [][]string
	queue := make([]string, 0)

	for taskID, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, taskID)
		}
	}

	for len(queue) > 0 {
		currentLevel := make([]string, len(queue))
		copy(currentLevel, queue)
		levels = append(levels, currentLevel)

		nextQueue := make([]string, 0)

		for _, taskID := range queue {
			for _, neighbor := range adjList[taskID] {
				inDegree[neighbor]--
				if inDegree[neighbor] == 0 {
					nextQueue = append(nextQueue, neighbor)
				}
			}
		}

		queue = nextQueue
	}

	totalProcessed := 0
	for _, level := range levels {
		totalProcessed += len(level)
	}

	if totalProcessed != len(w.dag.Nodes) {
		return nil, fmt.Errorf("circular dependency detected in workflow")
	}

	return levels, nil
}

// executeSequential executes tasks sequentially level by level
func (w *workflow) executeSequential(ctx context.Context, levels [][]string, executor TaskExecutor, result *golem.WorkflowResult) error {
	for levelIdx, level := range levels {
		w.logger.WithFields(logrus.Fields{
			"workflow_id": w.id,
			"level":       levelIdx,
			"task_count":  len(level),
		}).Debug("Executing workflow level")

		sortedLevel := w.sortTasksByPriority(level)

		for _, taskID := range sortedLevel {
			task, exists := w.tasks[taskID]
			if !exists {
				continue
			}

			if !w.areDependenciesSatisfied(task, result) {
				if w.config.FailurePolicy == golem.FailurePolicySkipOnError {
					w.logger.WithField("task_id", taskID).Warn("Skipping task due to unsatisfied dependencies")
					continue
				}
				return fmt.Errorf("dependencies not satisfied for task %s", taskID)
			}

			taskCtx, cancel := context.WithTimeout(ctx, task.GetConfig().Timeout)

			taskResult, err := executor.ExecuteTask(taskCtx, task)
			cancel()

			if err != nil {
				w.handleTaskError(task, err, result)
				if w.shouldStopOnError(err) {
					return fmt.Errorf("task %s failed: %w", taskID, err)
				}
				continue
			}

			result.TaskResults = append(result.TaskResults, *taskResult)
		}
	}

	return nil
}

// executeConcurrent executes tasks concurrently with level-based synchronization
func (w *workflow) executeConcurrent(ctx context.Context, levels [][]string, executor TaskExecutor, result *golem.WorkflowResult) error {
	var resultMu sync.Mutex

	for levelIdx, level := range levels {
		w.logger.WithFields(logrus.Fields{
			"workflow_id": w.id,
			"level":       levelIdx,
			"task_count":  len(level),
		}).Debug("Executing workflow level concurrently")

		semaphore := make(chan struct{}, w.config.MaxConcurrency)
		var wg sync.WaitGroup
		var levelErr error
		var levelErrMu sync.Mutex

		for _, taskID := range level {
			task, exists := w.tasks[taskID]
			if !exists {
				continue
			}

			wg.Add(1)
			go func(t golem.Task) {
				defer wg.Done()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				resultMu.Lock()
				depsSatisfied := w.areDependenciesSatisfied(t, result)
				resultMu.Unlock()

				if !depsSatisfied {
					if w.config.FailurePolicy == golem.FailurePolicySkipOnError {
						w.logger.WithField("task_id", t.ID()).Warn("Skipping task due to unsatisfied dependencies")
						return
					}

					levelErrMu.Lock()
					if levelErr == nil {
						levelErr = fmt.Errorf("dependencies not satisfied for task %s", t.ID())
					}
					levelErrMu.Unlock()
					return
				}

				taskCtx, cancel := context.WithTimeout(ctx, t.GetConfig().Timeout)
				defer cancel()

				taskResult, err := executor.ExecuteTask(taskCtx, t)

				if err != nil {
					levelErrMu.Lock()
					w.handleTaskError(t, err, result)
					if w.shouldStopOnError(err) && levelErr == nil {
						levelErr = fmt.Errorf("task %s failed: %w", t.ID(), err)
					}
					levelErrMu.Unlock()
					return
				}

				resultMu.Lock()
				result.TaskResults = append(result.TaskResults, *taskResult)
				resultMu.Unlock()
			}(task)
		}

		wg.Wait()

		if levelErr != nil {
			return levelErr
		}
	}

	return nil
}

// sortTasksByPriority sorts tasks by priority (higher priority first)
func (w *workflow) sortTasksByPriority(taskIDs []string) []string {
	type taskWithPriority struct {
		id       string
		priority int
	}

	taskPriorities := make([]taskWithPriority, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		if task, exists := w.tasks[taskID]; exists {
			taskPriorities = append(taskPriorities, taskWithPriority{
				id:       taskID,
				priority: task.GetConfig().Priority,
			})
		}
	}

	sort.Slice(taskPriorities, func(i, j int) bool {
		return taskPriorities[i].priority > taskPriorities[j].priority
	})

	sorted := make([]string, len(taskPriorities))
	for i, tp := range taskPriorities {
		sorted[i] = tp.id
	}

	return sorted
}

// areDependenciesSatisfied checks if all dependencies of a task are satisfied
func (w *workflow) areDependenciesSatisfied(task golem.Task, result *golem.WorkflowResult) bool {
	dependencies := task.GetDependencies()
	if len(dependencies) == 0 {
		return true
	}

	completedTasks := make(map[string]bool)
	for _, taskResult := range result.TaskResults {
		if taskResult.Success {
			completedTasks[taskResult.TaskID] = true
		}
	}

	for _, depID := range dependencies {
		if !completedTasks[depID] {
			return false
		}
	}

	return true
}

// handleTaskError handles task execution errors based on the failure policy
func (w *workflow) handleTaskError(task golem.Task, err error, result *golem.WorkflowResult) {
	w.logger.WithError(err).WithFields(logrus.Fields{
		"workflow_id": w.id,
		"task_id":     task.ID(),
		"task_name":   task.Name(),
	}).Error("Task execution failed")

	failedResult := golem.NewTaskResult(task.ID(), "")
	failedResult.Success = false
	failedResult.Error = err.Error()
	failedResult.Duration = 0

	result.TaskResults = append(result.TaskResults, *failedResult)
}

// shouldStopOnError determines if workflow should stop based on failure policy
func (w *workflow) shouldStopOnError(err error) bool {
	switch w.config.FailurePolicy {
	case golem.FailurePolicyStopOnError:
		return true
	case golem.FailurePolicyContinueOnError:
		return false
	case golem.FailurePolicySkipOnError:
		return false
	case golem.FailurePolicyRetryOnError:
		// TODO: Implement retry logic
		return false
	default:
		return true
	}
}

// GetTaskCount returns the number of tasks in the workflow
func (w *workflow) GetTaskCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.tasks)
}

// GetCreatedAt returns the creation timestamp
func (w *workflow) GetCreatedAt() time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.createdAt
}

// GetUpdatedAt returns the last update timestamp
func (w *workflow) GetUpdatedAt() time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.updatedAt
}

// GetConfig returns the workflow configuration
func (w *workflow) GetConfig() golem.WorkflowConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.config
}

// UpdateConfig updates the workflow configuration
func (w *workflow) UpdateConfig(config golem.WorkflowConfig) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.status == golem.WorkflowStatusRunning {
		return fmt.Errorf("cannot update configuration while workflow is running")
	}

	w.config = config
	w.updatedAt = time.Now()

	return nil
}
