// Package memory provides memory implementation for the Go Language Execution Model.
package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/sirupsen/logrus"
)

type BackendType int

const (
	BackendTypeMemory BackendType = iota
	BackendTypeRedis
	BackendTypePostgreSQL
	BackendTypeSQLite
)

// String returns the string representation of the backend type
func (bt BackendType) String() string {
	switch bt {
	case BackendTypeMemory:
		return "memory"
	case BackendTypeRedis:
		return "redis"
	case BackendTypePostgreSQL:
		return "postgresql"
	case BackendTypeSQLite:
		return "sqlite"
	default:
		return "unknown"
	}
}

type inMemoryBackend struct {
	data          map[string]interface{}
	conversations map[string][]golem.ConversationItem
	searchIndex   map[string][]golem.MemoryItem
	mu            sync.RWMutex
	logger        *logrus.Logger
}

// newInMemoryBackend creates a new in-memory backend
func newInMemoryBackend() *inMemoryBackend {
	return &inMemoryBackend{
		data:          make(map[string]interface{}),
		conversations: make(map[string][]golem.ConversationItem),
		searchIndex:   make(map[string][]golem.MemoryItem),
		logger:        logrus.New(),
	}
}

// Store saves data to memory with the given key
func (b *inMemoryBackend) Store(ctx context.Context, key string, data interface{}) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[key] = data

	if item, ok := data.(golem.MemoryItem); ok {
		words := extractKeywords(fmt.Sprintf("%v", item.Data))
		for _, word := range words {
			b.searchIndex[word] = append(b.searchIndex[word], item)
		}
	}

	b.logger.WithField("key", key).Debug("Data stored in memory")
	return nil
}

// Retrieve gets data from memory by key
func (b *inMemoryBackend) Retrieve(ctx context.Context, key string) (interface{}, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	data, exists := b.data[key]
	if !exists {
		return nil, fmt.Errorf("key %s not found in memory", key)
	}

	b.logger.WithField("key", key).Debug("Data retrieved from memory")
	return data, nil
}

// Delete removes data from memory
func (b *inMemoryBackend) Delete(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.data, key)
	b.logger.WithField("key", key).Debug("Data deleted from memory")
	return nil
}

// Search performs a semantic search in memory
func (b *inMemoryBackend) Search(ctx context.Context, query string, limit int) ([]golem.MemoryItem, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	queryWords := extractKeywords(query)
	itemScores := make(map[string]float64)
	itemMap := make(map[string]golem.MemoryItem)

	for _, word := range queryWords {
		if items, exists := b.searchIndex[word]; exists {
			for _, item := range items {
				score := itemScores[item.ID] + 1.0
				itemScores[item.ID] = score
				itemMap[item.ID] = item
			}
		}
	}

	var results []golem.MemoryItem
	for itemID, score := range itemScores {
		item := itemMap[itemID]
		item.Score = score
		results = append(results, item)
	}

	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Score < results[j].Score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	b.logger.WithFields(logrus.Fields{
		"query":         query,
		"results_count": len(results),
	}).Debug("Memory search completed")

	return results, nil
}

// GetConversationHistory returns the conversation history for an agent
func (b *inMemoryBackend) GetConversationHistory(ctx context.Context, agentID string, limit int) ([]golem.ConversationItem, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	history, exists := b.conversations[agentID]
	if !exists {
		return []golem.ConversationItem{}, nil
	}

	start := 0
	if limit > 0 && len(history) > limit {
		start = len(history) - limit
	}

	result := make([]golem.ConversationItem, len(history)-start)
	copy(result, history[start:])

	b.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"count":    len(result),
	}).Debug("Conversation history retrieved")

	return result, nil
}

// AddToConversation adds a message to the conversation history
func (b *inMemoryBackend) AddToConversation(ctx context.Context, agentID string, item golem.ConversationItem) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conversations[agentID] == nil {
		b.conversations[agentID] = make([]golem.ConversationItem, 0)
	}

	b.conversations[agentID] = append(b.conversations[agentID], item)

	b.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"role":     item.Role,
	}).Debug("Message added to conversation history")

	return nil
}

// Clear clears all memory data
func (b *inMemoryBackend) Clear(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data = make(map[string]interface{})
	b.conversations = make(map[string][]golem.ConversationItem)
	b.searchIndex = make(map[string][]golem.MemoryItem)

	b.logger.Info("Memory cleared")
	return nil
}

type memory struct {
	backend golem.Memory
	config  golem.MemoryConfig
	logger  *logrus.Logger
}

// NewMemory creates a new memory instance with the specified configuration
func NewMemory(config golem.MemoryConfig) golem.Memory {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	var backend golem.Memory

	switch config.Backend {
	case "redis":
		backend = newRedisBackend(config, logger)
	case "postgresql":
		backend = newPostgreSQLBackend(config, logger)
	case "sqlite":
		backend = newSQLiteBackend(config, logger)
	default:
		backend = newInMemoryBackend()
	}

	return &memory{
		backend: backend,
		config:  config,
		logger:  logger,
	}
}

// Store saves data to memory with the given key
func (m *memory) Store(ctx context.Context, key string, data interface{}) error {
	return m.backend.Store(ctx, key, data)
}

// Retrieve gets data from memory by key
func (m *memory) Retrieve(ctx context.Context, key string) (interface{}, error) {
	return m.backend.Retrieve(ctx, key)
}

// Delete removes data from memory
func (m *memory) Delete(ctx context.Context, key string) error {
	return m.backend.Delete(ctx, key)
}

// Search performs a semantic search in memory
func (m *memory) Search(ctx context.Context, query string, limit int) ([]golem.MemoryItem, error) {
	return m.backend.Search(ctx, query, limit)
}

// GetConversationHistory returns the conversation history for an agent
func (m *memory) GetConversationHistory(ctx context.Context, agentID string, limit int) ([]golem.ConversationItem, error) {
	return m.backend.GetConversationHistory(ctx, agentID, limit)
}

// AddToConversation adds a message to the conversation history
func (m *memory) AddToConversation(ctx context.Context, agentID string, item golem.ConversationItem) error {
	return m.backend.AddToConversation(ctx, agentID, item)
}

// Clear clears all memory data
func (m *memory) Clear(ctx context.Context) error {
	return m.backend.Clear(ctx)
}

// extractKeywords extracts keywords from text for simple search indexing
func extractKeywords(text string) []string {
	// TODO: implement keyword extraction based on a predefined set of key
	words := strings.Fields(strings.ToLower(text))

	wordMap := make(map[string]bool)
	var uniqueWords []string

	for _, word := range words {
		if len(word) > 2 && !wordMap[word] {
			wordMap[word] = true
			uniqueWords = append(uniqueWords, word)
		}
	}

	return uniqueWords
}

type MemoryManager struct {
	memories map[string]golem.Memory
	mu       sync.RWMutex
	logger   *logrus.Logger
}

// NewMemoryManager creates a new memory manager
func NewMemoryManager() *MemoryManager {
	return &MemoryManager{
		memories: make(map[string]golem.Memory),
		logger:   logrus.New(),
	}
}

// CreateMemory creates a new memory instance with the given name and configuration
func (mm *MemoryManager) CreateMemory(name string, config golem.MemoryConfig) (golem.Memory, error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if _, exists := mm.memories[name]; exists {
		return nil, fmt.Errorf("memory instance %s already exists", name)
	}

	memory := NewMemory(config)
	mm.memories[name] = memory

	mm.logger.WithFields(logrus.Fields{
		"name":    name,
		"backend": config.Backend,
	}).Info("Memory instance created")

	return memory, nil
}

// GetMemory retrieves a memory instance by name
func (mm *MemoryManager) GetMemory(name string) (golem.Memory, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	memory, exists := mm.memories[name]
	if !exists {
		return nil, fmt.Errorf("memory instance %s not found", name)
	}

	return memory, nil
}

// DeleteMemory deletes a memory instance
func (mm *MemoryManager) DeleteMemory(name string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if _, exists := mm.memories[name]; !exists {
		return fmt.Errorf("memory instance %s not found", name)
	}

	delete(mm.memories, name)
	mm.logger.WithField("name", name).Info("Memory instance deleted")
	return nil
}

// ListMemories returns the names of all memory instances
func (mm *MemoryManager) ListMemories() []string {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	names := make([]string, 0, len(mm.memories))
	for name := range mm.memories {
		names = append(names, name)
	}

	return names
}

// ClearAll clears all memory instances
func (mm *MemoryManager) ClearAll(ctx context.Context) error {
	mm.mu.RLock()
	memories := make([]golem.Memory, 0, len(mm.memories))
	for _, memory := range mm.memories {
		memories = append(memories, memory)
	}
	mm.mu.RUnlock()

	for _, memory := range memories {
		if err := memory.Clear(ctx); err != nil {
			mm.logger.WithError(err).Warn("Failed to clear memory instance")
		}
	}

	mm.logger.Info("All memory instances cleared")
	return nil
}
