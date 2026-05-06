package buffer

import (
	"sync"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type QueueStats struct {
	Queued      int64  `json:"queued"`
	Forwarded   int64  `json:"forwarded"`
	Failed      int64  `json:"failed"`
	LastSuccess string `json:"last_success"`
	LastFailure string `json:"last_failure"`
	Paused      bool   `json:"paused"`
}

type Queue struct {
	ch chan event.Event

	mu    sync.RWMutex
	stats QueueStats
}

func NewQueue(size int) *Queue {
	if size < 100 {
		size = 100
	}
	return &Queue{
		ch: make(chan event.Event, size),
	}
}

func (q *Queue) Push(evt event.Event) bool {
	select {
	case q.ch <- evt:
		q.mu.Lock()
		q.stats.Queued++
		q.mu.Unlock()
		return true
	default:
		return false
	}
}

func (q *Queue) PopBatch(max int, wait time.Duration) []event.Event {
	if max <= 0 {
		max = 1
	}
	first, ok := q.popOne(wait)
	if !ok {
		return nil
	}
	out := make([]event.Event, 0, max)
	out = append(out, first)
	for len(out) < max {
		select {
		case e := <-q.ch:
			out = append(out, e)
		default:
			return out
		}
	}
	return out
}

func (q *Queue) popOne(wait time.Duration) (event.Event, bool) {
	if wait <= 0 {
		wait = 100 * time.Millisecond
	}
	select {
	case e := <-q.ch:
		return e, true
	case <-time.After(wait):
		return event.Event{}, false
	}
}

func (q *Queue) MarkSuccess(n int, when string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stats.Queued -= int64(n)
	if q.stats.Queued < 0 {
		q.stats.Queued = 0
	}
	q.stats.Forwarded += int64(n)
	q.stats.LastSuccess = when
}

func (q *Queue) MarkFailure(n int, when string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stats.Failed += int64(n)
	q.stats.LastFailure = when
}

func (q *Queue) Snapshot() QueueStats {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.stats
}

func (q *Queue) SetPaused(v bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stats.Paused = v
}

func (q *Queue) IsPaused() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.stats.Paused
}
