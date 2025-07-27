package golem

import (
	"sync"
)

type eventBus struct {
	handlers map[EventType][]EventHandler
	mu       sync.RWMutex
}

// NewEventBus creates a new event bus
func NewEventBus() EventBus {
	return &eventBus{
		handlers: make(map[EventType][]EventHandler),
	}
}

func (eb *eventBus) Subscribe(eventType EventType, handler EventHandler) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.handlers[eventType] == nil {
		eb.handlers[eventType] = make([]EventHandler, 0)
	}

	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
	return nil
}

func (eb *eventBus) Unsubscribe(eventType EventType, handler EventHandler) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	handlers, exists := eb.handlers[eventType]
	if !exists {
		return nil
	}

	for i, h := range handlers {
		if &h == &handler {
			eb.handlers[eventType] = append(handlers[:i], handlers[i+1:]...)
			break
		}
	}

	return nil
}

func (eb *eventBus) Publish(event Event) error {
	eb.mu.RLock()
	handlers := make([]EventHandler, len(eb.handlers[event.Type]))
	copy(handlers, eb.handlers[event.Type])
	eb.mu.RUnlock()
	for _, handler := range handlers {
		go func(h EventHandler) {
			defer func() {
				if r := recover(); r != nil {
					// TODO: Handle panic gracefully, maybe log it
					// log.Printf("Recovered from panic in event handler: %v", r)
				}
			}()

			h(event)
		}(handler)
	}

	return nil
}

// Close shuts down the event bus
func (eb *eventBus) Close() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.handlers = make(map[EventType][]EventHandler)
	return nil
}
