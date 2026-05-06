package api

import (
	"sync"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type StreamHub struct {
	mu      sync.RWMutex
	nextID  int
	clients map[int]chan event.Event
}

func NewStreamHub() *StreamHub {
	return &StreamHub{clients: map[int]chan event.Event{}}
}

func (h *StreamHub) Subscribe() (int, <-chan event.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.nextID
	h.nextID++
	ch := make(chan event.Event, 128)
	h.clients[id] = ch
	return id, ch
}

func (h *StreamHub) Unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.clients[id]
	if ok {
		close(ch)
		delete(h.clients, id)
	}
}

func (h *StreamHub) Publish(e event.Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.clients {
		select {
		case ch <- e:
		default:
		}
	}
}

