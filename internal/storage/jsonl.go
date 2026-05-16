package storage

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type EventQuery struct {
	Limit      int
	SourceType string
	Severity   string
	Category   string
	Asset      string
	Search     string
}

type StoredRecord struct {
	Event             event.Event      `json:"event"`
	OriginalEventJSON json.RawMessage `json:"original_event_json"`
}

type JSONLStore struct {
	path string
	mu   sync.Mutex
}

func NewJSONLStore(path string) *JSONLStore {
	return &JSONLStore{path: path}
}

func (s *JSONLStore) Append(evt event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	rec := StoredRecord{Event: evt, OriginalEventJSON: evt.OriginalRaw}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

func (s *JSONLStore) ReadFiltered(q EventQuery) ([]event.Event, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []event.Event{}, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	out := make([]event.Event, 0, q.Limit)
	for scanner.Scan() {
		var rec StoredRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if len(rec.OriginalEventJSON) > 0 {
			rec.Event.OriginalRaw = append(json.RawMessage(nil), rec.OriginalEventJSON...)
		}
		if !matches(rec.Event, q) {
			continue
		}
		out = append(out, rec.Event)
		if len(out) > q.Limit {
			out = out[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *JSONLStore) ReadByID(id string) (event.Event, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return event.Event{}, false, nil
		}
		return event.Event{}, false, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec StoredRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if len(rec.OriginalEventJSON) > 0 {
			rec.Event.OriginalRaw = append(json.RawMessage(nil), rec.OriginalEventJSON...)
		}
		if rec.Event.ID == id {
			return rec.Event, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return event.Event{}, false, err
	}
	return event.Event{}, false, nil
}

func (s *JSONLStore) LoadIDSet() (map[string]struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]struct{}{}
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec StoredRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if len(rec.OriginalEventJSON) > 0 {
			rec.Event.OriginalRaw = append(json.RawMessage(nil), rec.OriginalEventJSON...)
		}
		if rec.Event.ID != "" {
			out[rec.Event.ID] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *JSONLStore) LoadAll() ([]event.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []event.Event{}, nil
		}
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	out := make([]event.Event, 0, 512)
	for scanner.Scan() {
		var rec StoredRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if len(rec.OriginalEventJSON) > 0 {
			rec.Event.OriginalRaw = append(json.RawMessage(nil), rec.OriginalEventJSON...)
		}
		out = append(out, rec.Event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func matches(e event.Event, q EventQuery) bool {
	if q.SourceType != "" && !strings.EqualFold(e.SourceType, q.SourceType) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(e.Severity, q.Severity) {
		return false
	}
	if q.Category != "" && !strings.EqualFold(e.EventCategory, q.Category) {
		return false
	}
	if q.Asset != "" {
		match := strings.EqualFold(e.AssetIP, q.Asset) || strings.EqualFold(e.AssetName, q.Asset)
		if !match {
			return false
		}
	}
	if q.Search != "" {
		s := strings.ToLower(q.Search)
		blob := strings.ToLower(strings.Join([]string{
			e.Message, e.Raw, e.AssetName, e.AssetIP, e.EventCategory, e.SourceType, e.Severity, e.ID,
		}, " "))
		if !strings.Contains(blob, s) {
			for k, v := range e.Tags {
				if strings.Contains(strings.ToLower(k), s) || strings.Contains(strings.ToLower(toString(v)), s) {
					return true
				}
			}
			return false
		}
	}
	return true
}

func toString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
