package store

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sir-labs/sir-auth/internal/model"
)

// Buffered request logging: /session/verify must never wait on the DB, so events go
// into a channel and one goroutine writes them in batches.
const (
	usageBuffer   = 10000
	usageBatch    = 500
	usageInterval = 2 * time.Second
)

var usage struct {
	mu      sync.RWMutex
	ch      chan model.RequestLog
	done    chan struct{}
	dropped atomic.Int64
}

// StartUsage starts the background flusher. Call once at boot.
func StartUsage(s *Store) {
	usage.mu.Lock()
	defer usage.mu.Unlock()
	usage.ch = make(chan model.RequestLog, usageBuffer)
	usage.done = make(chan struct{})
	go flushLoop(s, usage.ch, usage.done)
}

// LogUsage queues an event without blocking. It is a no-op before StartUsage or after
// CloseUsage, and counts the event as dropped when the buffer is full.
func LogUsage(e model.RequestLog) {
	usage.mu.RLock()
	defer usage.mu.RUnlock()
	if usage.ch == nil {
		return
	}
	select {
	case usage.ch <- e:
	default:
		usage.dropped.Add(1)
	}
}

// UsageDropped is how many events were dropped because the buffer was full (since boot).
func UsageDropped() int64 { return usage.dropped.Load() }

// CloseUsage stops accepting events and waits until everything queued is written.
func CloseUsage() {
	usage.mu.Lock()
	ch, done := usage.ch, usage.done
	usage.ch = nil
	usage.mu.Unlock()
	if ch == nil {
		return
	}
	close(ch)
	<-done
}

func flushLoop(s *Store, ch <-chan model.RequestLog, done chan<- struct{}) {
	defer close(done)
	batch := make([]model.RequestLog, 0, usageBatch)
	tick := time.NewTicker(usageInterval)
	defer tick.Stop()
	flush := func() {
		if len(batch) > 0 {
			s.writeUsage(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= usageBatch {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// writeUsage inserts a batch and updates last_used_at/ip of the tokens in it.
// On error the batch is logged and dropped (no retry loop).
func (s *Store) writeUsage(batch []model.RequestLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.db.WithContext(ctx).CreateInBatches(batch, usageBatch).Error; err != nil {
		usage.dropped.Add(int64(len(batch)))
		log.Printf("usage: dropped %d events: %v", len(batch), err)
		return
	}
	last := map[string]model.RequestLog{}
	for _, e := range batch {
		if e.TokenID != nil && e.TS.After(last[*e.TokenID].TS) {
			last[*e.TokenID] = e
		}
	}
	for id, e := range last {
		err := s.db.WithContext(ctx).Model(&model.APIToken{}).Where("id = ?", id).
			Updates(map[string]any{"last_used_at": e.TS.Unix(), "last_used_ip": e.IP}).Error
		if err != nil {
			log.Printf("usage: token %s last_used: %v", id, err)
		}
	}
}
