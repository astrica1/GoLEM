// Package memory provides Redis backend implementation for memory storage.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type redisBackend struct {
	client *redis.Client
	config golem.MemoryConfig
	logger *logrus.Logger
}

// newRedisBackend creates a new Redis backend
func newRedisBackend(config golem.MemoryConfig, logger *logrus.Logger) golem.Memory {
	redisConfig, ok := config.Config["redis"].(map[string]interface{})
	if !ok {
		redisConfig = make(map[string]interface{})
	}

	addr, _ := redisConfig["addr"].(string)
	if addr == "" {
		addr = "localhost:6379"
	}

	password, _ := redisConfig["password"].(string)
	db, _ := redisConfig["db"].(int)

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	backend := &redisBackend{
		client: client,
		config: config,
		logger: logger,
	}

	logger.WithFields(logrus.Fields{
		"backend": "redis",
		"addr":    addr,
		"db":      db,
	}).Info("Redis memory backend initialized")

	return backend
}

// Store saves data to Redis with the given key
func (b *redisBackend) Store(ctx context.Context, key string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	var ttl time.Duration
	if b.config.TTL > 0 {
		ttl = b.config.TTL
	}

	err = b.client.Set(ctx, key, jsonData, ttl).Err()
	if err != nil {
		b.logger.WithError(err).WithField("key", key).Error("Failed to store data in Redis")
		return fmt.Errorf("failed to store data in redis: %w", err)
	}

	b.logger.WithField("key", key).Debug("Data stored in Redis")
	return nil
}

// Retrieve gets data from Redis by key
func (b *redisBackend) Retrieve(ctx context.Context, key string) (interface{}, error) {
	val, err := b.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("key %s not found", key)
	} else if err != nil {
		b.logger.WithError(err).WithField("key", key).Error("Failed to retrieve data from Redis")
		return nil, fmt.Errorf("failed to retrieve data from redis: %w", err)
	}

	var data interface{}
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	b.logger.WithField("key", key).Debug("Data retrieved from Redis")
	return data, nil
}

// Delete removes data from Redis
func (b *redisBackend) Delete(ctx context.Context, key string) error {
	err := b.client.Del(ctx, key).Err()
	if err != nil {
		b.logger.WithError(err).WithField("key", key).Error("Failed to delete data from Redis")
		return fmt.Errorf("failed to delete data from redis: %w", err)
	}

	b.logger.WithField("key", key).Debug("Data deleted from Redis")
	return nil
}

// Search performs a search in Redis (simplified implementation)
func (b *redisBackend) Search(ctx context.Context, query string, limit int) ([]golem.MemoryItem, error) {
	// TODO: Implement search logic in Redis
	b.logger.WithField("query", query).Debug("Redis search requested (not implemented)")
	return []golem.MemoryItem{}, nil
}

// GetConversationHistory returns the conversation history for an agent
func (b *redisBackend) GetConversationHistory(ctx context.Context, agentID string, limit int) ([]golem.ConversationItem, error) {
	key := fmt.Sprintf("conversation:%s", agentID)

	var start, stop int64 = 0, -1
	if limit > 0 {
		start = -int64(limit)
	}

	vals, err := b.client.LRange(ctx, key, start, stop).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get conversation history: %w", err)
	}

	history := make([]golem.ConversationItem, len(vals))
	for i, val := range vals {
		if err := json.Unmarshal([]byte(val), &history[i]); err != nil {
			b.logger.WithError(err).Warn("Failed to unmarshal conversation item")
			continue
		}
	}

	b.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"count":    len(history),
	}).Debug("Conversation history retrieved from Redis")

	return history, nil
}

// AddToConversation adds a message to the conversation history
func (b *redisBackend) AddToConversation(ctx context.Context, agentID string, item golem.ConversationItem) error {
	key := fmt.Sprintf("conversation:%s", agentID)

	jsonData, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal conversation item: %w", err)
	}

	err = b.client.RPush(ctx, key, jsonData).Err()
	if err != nil {
		return fmt.Errorf("failed to add to conversation: %w", err)
	}

	if b.config.MaxSize > 0 {
		b.client.LTrim(ctx, key, -int64(b.config.MaxSize), -1)
	}

	b.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"role":     item.Role,
	}).Debug("Message added to Redis conversation history")

	return nil
}

// Clear clears all memory data
func (b *redisBackend) Clear(ctx context.Context) error {
	err := b.client.FlushDB(ctx).Err()
	if err != nil {
		return fmt.Errorf("failed to clear redis database: %w", err)
	}

	b.logger.Info("Redis database cleared")
	return nil
}
