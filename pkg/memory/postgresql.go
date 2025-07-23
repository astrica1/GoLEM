// Package memory provides PostgreSQL backend implementation for memory storage.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type postgresBackend struct {
	db     *gorm.DB
	config golem.MemoryConfig
	logger *logrus.Logger
}

type MemoryRecord struct {
	ID        uint   `gorm:"primarykey"`
	Key       string `gorm:"uniqueIndex;size:255"`
	Data      string `gorm:"type:text"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ConversationRecord struct {
	ID        uint      `gorm:"primarykey"`
	AgentID   string    `gorm:"index;size:255"`
	Role      string    `gorm:"size:50"`
	Content   string    `gorm:"type:text"`
	Metadata  string    `gorm:"type:jsonb"`
	Timestamp time.Time `gorm:"index"`
	CreatedAt time.Time
}

// newPostgreSQLBackend creates a new PostgreSQL backend
func newPostgreSQLBackend(config golem.MemoryConfig, logger *logrus.Logger) golem.Memory {
	postgresConfig, ok := config.Config["postgresql"].(map[string]interface{})
	if !ok {
		postgresConfig = make(map[string]interface{})
	}

	dsn, _ := postgresConfig["dsn"].(string)
	if dsn == "" {
		dsn = "host=localhost user=postgres dbname=golem_memory sslmode=disable"
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to PostgreSQL")
	}

	db.AutoMigrate(&MemoryRecord{}, &ConversationRecord{})
	backend := &postgresBackend{
		db:     db,
		config: config,
		logger: logger,
	}

	logger.WithField("backend", "postgresql").Info("PostgreSQL memory backend initialized")
	return backend
}

// Store saves data to PostgreSQL with the given key
func (b *postgresBackend) Store(ctx context.Context, key string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	record := MemoryRecord{
		Key:  key,
		Data: string(jsonData),
	}

	result := b.db.WithContext(ctx).Where("key = ?", key).FirstOrCreate(&record)
	if result.Error != nil {
		b.logger.WithError(result.Error).WithField("key", key).Error("Failed to store data in PostgreSQL")
		return fmt.Errorf("failed to store data: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		b.db.WithContext(ctx).Model(&record).Where("key = ?", key).Update("data", string(jsonData))
	}

	b.logger.WithField("key", key).Debug("Data stored in PostgreSQL")
	return nil
}

// Retrieve gets data from PostgreSQL by key
func (b *postgresBackend) Retrieve(ctx context.Context, key string) (interface{}, error) {
	var record MemoryRecord
	result := b.db.WithContext(ctx).Where("key = ?", key).First(&record)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("key %s not found", key)
		}
		return nil, fmt.Errorf("failed to retrieve data: %w", result.Error)
	}

	var data interface{}
	if err := json.Unmarshal([]byte(record.Data), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	b.logger.WithField("key", key).Debug("Data retrieved from PostgreSQL")
	return data, nil
}

// Delete removes data from PostgreSQL
func (b *postgresBackend) Delete(ctx context.Context, key string) error {
	result := b.db.WithContext(ctx).Where("key = ?", key).Delete(&MemoryRecord{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete data: %w", result.Error)
	}

	b.logger.WithField("key", key).Debug("Data deleted from PostgreSQL")
	return nil
}

// Search performs a search in PostgreSQL
func (b *postgresBackend) Search(ctx context.Context, query string, limit int) ([]golem.MemoryItem, error) {
	var records []MemoryRecord
	db := b.db.WithContext(ctx).Where("data ILIKE ?", "%"+query+"%")

	if limit > 0 {
		db = db.Limit(limit)
	}

	if err := db.Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to search data: %w", err)
	}

	items := make([]golem.MemoryItem, len(records))
	for i, record := range records {
		var data interface{}
		json.Unmarshal([]byte(record.Data), &data)

		items[i] = golem.MemoryItem{
			ID:        fmt.Sprintf("%d", record.ID),
			Key:       record.Key,
			Data:      data,
			Score:     1.0,
			CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt,
		}
	}

	b.logger.WithFields(logrus.Fields{
		"query":         query,
		"results_count": len(items),
	}).Debug("PostgreSQL search completed")

	return items, nil
}

// GetConversationHistory returns the conversation history for an agent
func (b *postgresBackend) GetConversationHistory(ctx context.Context, agentID string, limit int) ([]golem.ConversationItem, error) {
	var records []ConversationRecord
	db := b.db.WithContext(ctx).Where("agent_id = ?", agentID).Order("timestamp DESC")

	if limit > 0 {
		db = db.Limit(limit)
	}

	if err := db.Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to get conversation history: %w", err)
	}

	history := make([]golem.ConversationItem, len(records))
	for i, record := range records {
		var metadata map[string]interface{}
		json.Unmarshal([]byte(record.Metadata), &metadata)

		history[i] = golem.ConversationItem{
			ID:        fmt.Sprintf("%d", record.ID),
			AgentID:   record.AgentID,
			Role:      record.Role,
			Content:   record.Content,
			Metadata:  metadata,
			Timestamp: record.Timestamp,
		}
	}

	b.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"count":    len(history),
	}).Debug("Conversation history retrieved from PostgreSQL")

	return history, nil
}

// AddToConversation adds a message to the conversation history
func (b *postgresBackend) AddToConversation(ctx context.Context, agentID string, item golem.ConversationItem) error {
	metadataJSON, _ := json.Marshal(item.Metadata)

	record := ConversationRecord{
		AgentID:   agentID,
		Role:      item.Role,
		Content:   item.Content,
		Metadata:  string(metadataJSON),
		Timestamp: item.Timestamp,
	}

	if err := b.db.WithContext(ctx).Create(&record).Error; err != nil {
		return fmt.Errorf("failed to add conversation item: %w", err)
	}

	if b.config.MaxSize > 0 {
		var count int64
		b.db.WithContext(ctx).Model(&ConversationRecord{}).Where("agent_id = ?", agentID).Count(&count)

		if count > int64(b.config.MaxSize) {
			excess := count - int64(b.config.MaxSize)
			b.db.WithContext(ctx).Where("agent_id = ?", agentID).
				Order("timestamp ASC").Limit(int(excess)).Delete(&ConversationRecord{})
		}
	}

	b.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"role":     item.Role,
	}).Debug("Message added to PostgreSQL conversation history")

	return nil
}

// Clear clears all memory data
func (b *postgresBackend) Clear(ctx context.Context) error {
	if err := b.db.WithContext(ctx).Exec("TRUNCATE memory_records, conversation_records").Error; err != nil {
		return fmt.Errorf("failed to clear database: %w", err)
	}

	b.logger.Info("PostgreSQL database cleared")
	return nil
}
