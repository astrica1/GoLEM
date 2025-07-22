package task

import (
	"fmt"
	"testing"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/stretchr/testify/assert"
)

func TestNewTask(t *testing.T) {
	config := Config{
		Name:          "Test Task",
		Description:   "A test task for unit testing",
		Priority:      5,
		Timeout:       2 * time.Minute,
		RetryCount:    3,
		RequiredTools: []string{"calculator"},
		Dependencies:  []string{"dependency-task-1"},
		Input: golem.TaskInput{
			Text: "Process this input",
			Parameters: map[string]interface{}{
				"param1": "value1",
				"param2": 42,
			},
			Context: map[string]interface{}{
				"context1": "contextValue1",
			},
		},
	}

	task := NewTask("test-task", config)

	assert.NotNil(t, task)
	assert.Equal(t, "Test Task", task.Name())
	assert.Equal(t, "A test task for unit testing", task.Description())
	assert.NotEmpty(t, task.ID())
	assert.Equal(t, golem.TaskStatusPending, task.GetStatus())

	taskConfig := task.GetConfig()
	assert.Equal(t, 5, taskConfig.Priority)
	assert.Equal(t, 2*time.Minute, taskConfig.Timeout)
	assert.Equal(t, 3, taskConfig.RetryCount)
	assert.Contains(t, taskConfig.RequiredTools, "calculator")

	taskInput := task.GetInput()
	assert.Equal(t, "Process this input", taskInput.Text)
	assert.Equal(t, "value1", taskInput.Parameters["param1"])
	assert.Equal(t, 42, taskInput.Parameters["param2"])
	assert.Equal(t, "contextValue1", taskInput.Context["context1"])

	dependencies := task.GetDependencies()
	assert.Contains(t, dependencies, "dependency-task-1")
}

func TestTaskWithDefaults(t *testing.T) {
	config := Config{
		Name:        "Minimal Task",
		Description: "Task with minimal configuration",
	}

	task := NewTask("minimal-task", config)

	assert.NotNil(t, task)
	assert.Equal(t, "Minimal Task", task.Name())

	taskConfig := task.GetConfig()
	assert.Equal(t, 5*time.Minute, taskConfig.Timeout)
	assert.Equal(t, 3, taskConfig.RetryCount)
	assert.NotNil(t, taskConfig.CustomConfig)
}

func TestTaskSetAndGetResult(t *testing.T) {
	config := Config{
		Name:        "Result Test Task",
		Description: "Testing result operations",
	}

	task := NewTask("result-task", config)
	assert.Nil(t, task.GetResult())

	result := &golem.TaskResult{
		ID:         "result-1",
		TaskID:     task.ID(),
		Output:     "Task completed successfully",
		Success:    true,
		TokensUsed: 25,
		Duration:   1 * time.Second,
	}

	task.SetResult(result)
	retrievedResult := task.GetResult()

	assert.NotNil(t, retrievedResult)
	assert.Equal(t, result.ID, retrievedResult.ID)
	assert.Equal(t, result.Output, retrievedResult.Output)
	assert.True(t, retrievedResult.Success)
	assert.Equal(t, 25, retrievedResult.TokensUsed)
}

func TestTaskStatusOperations(t *testing.T) {
	config := Config{
		Name: "Status Test Task",
	}

	task := NewTask("status-task", config)

	assert.Equal(t, golem.TaskStatusPending, task.GetStatus())
	task.SetStatus(golem.TaskStatusRunning)
	assert.Equal(t, golem.TaskStatusRunning, task.GetStatus())
	task.SetStatus(golem.TaskStatusCompleted)
	assert.Equal(t, golem.TaskStatusCompleted, task.GetStatus())
	task.SetStatus(golem.TaskStatusFailed)
	assert.Equal(t, golem.TaskStatusFailed, task.GetStatus())
	task.SetStatus(golem.TaskStatusCancelled)
	assert.Equal(t, golem.TaskStatusCancelled, task.GetStatus())
}

func TestTaskGettersAreThreadSafe(t *testing.T) {
	config := Config{
		Name:         "Thread Safety Test",
		Description:  "Testing thread safety",
		Dependencies: []string{"dep1", "dep2"},
	}

	task := NewTask("thread-safe-task", config)
	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func() {
			defer func() { done <- true }()

			_ = task.ID()
			_ = task.Name()
			_ = task.Description()
			_ = task.GetInput()
			_ = task.GetConfig()
			_ = task.GetDependencies()
			_ = task.GetStatus()
			_ = task.GetResult()
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestTaskSettersAreThreadSafe(t *testing.T) {
	config := Config{
		Name: "Thread Safety Setters Test",
	}

	task := NewTask("setter-thread-safe-task", config)

	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func(index int) {
			defer func() { done <- true }()

			if index%2 == 0 {
				task.SetStatus(golem.TaskStatusRunning)
			} else {
				task.SetStatus(golem.TaskStatusPending)
			}

			result := &golem.TaskResult{
				ID:     fmt.Sprintf("result-%d", index),
				Output: fmt.Sprintf("Output %d", index),
			}
			task.SetResult(result)
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	assert.NotNil(t, task.GetResult())
	status := task.GetStatus()
	assert.True(t, status == golem.TaskStatusRunning || status == golem.TaskStatusPending)
}

func TestTaskUpdateTime(t *testing.T) {
	config := Config{
		Name: "Update Time Test",
	}

	task := NewTask("update-time-task", config)

	time.Sleep(10 * time.Millisecond)

	task.SetStatus(golem.TaskStatusRunning)

	result := &golem.TaskResult{
		ID:     "time-test-result",
		Output: "Updated result",
	}
	task.SetResult(result)
	assert.NotNil(t, task.GetResult())
}

func TestTaskDependenciesCopy(t *testing.T) {
	dependencies := []string{"dep1", "dep2", "dep3"}
	config := Config{
		Name:         "Dependencies Copy Test",
		Dependencies: dependencies,
	}

	task := NewTask("deps-copy-task", config)
	taskDeps := task.GetDependencies()
	dependencies[0] = "modified"
	assert.Equal(t, "dep1", taskDeps[0])
	assert.NotEqual(t, "modified", taskDeps[0])
	taskDeps[1] = "modified-task-dep"
	freshDeps := task.GetDependencies()
	assert.Equal(t, "dep2", freshDeps[1])
	assert.NotEqual(t, "modified-task-dep", freshDeps[1])
}

func BenchmarkNewTask(b *testing.B) {
	config := Config{
		Name:        "Benchmark Task",
		Description: "Task for benchmarking",
		Priority:    5,
		Timeout:     1 * time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		task := NewTask(fmt.Sprintf("benchmark-task-%d", i), config)
		_ = task
	}
}

func BenchmarkTaskGetters(b *testing.B) {
	config := Config{
		Name:         "Benchmark Getters Task",
		Description:  "Task for benchmarking getters",
		Dependencies: []string{"dep1", "dep2", "dep3"},
	}

	task := NewTask("getters-benchmark-task", config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = task.ID()
		_ = task.Name()
		_ = task.Description()
		_ = task.GetInput()
		_ = task.GetConfig()
		_ = task.GetDependencies()
		_ = task.GetStatus()
	}
}

func BenchmarkTaskSetters(b *testing.B) {
	config := Config{
		Name: "Benchmark Setters Task",
	}

	task := NewTask("setters-benchmark-task", config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		task.SetStatus(golem.TaskStatusRunning)

		result := &golem.TaskResult{
			ID:     fmt.Sprintf("bench-result-%d", i),
			Output: fmt.Sprintf("Benchmark output %d", i),
		}
		task.SetResult(result)
	}
}
