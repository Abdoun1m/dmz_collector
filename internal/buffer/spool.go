package buffer

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type SpoolRecord struct {
	Offset int64      `json:"offset"`
	Event  event.Event `json:"event"`
}

type checkpoint struct {
	LastForwardedOffset int64 `json:"last_forwarded_offset"`
}

type Spool struct {
	mu             sync.Mutex
	path           string
	checkpointPath string
}

func NewSpool(path string) *Spool {
	return &Spool{
		path:           path,
		checkpointPath: filepath.Join(filepath.Dir(path), "checkpoint.json"),
	}
}

func (s *Spool) Append(evt event.Event) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	record := SpoolRecord{Offset: info.Size(), Event: evt}
	b, err := json.Marshal(record)
	if err != nil {
		return 0, err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return 0, err
	}
	return record.Offset, nil
}

func (s *Spool) LoadPending() ([]SpoolRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := checkpoint{}
	_ = s.readCheckpointLocked(&cp)

	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	out := make([]SpoolRecord, 0, 512)
	for scanner.Scan() {
		var rec SpoolRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Offset <= cp.LastForwardedOffset {
			continue
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Spool) MarkForwarded(offset int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := checkpoint{LastForwardedOffset: offset}
	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.checkpointPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.checkpointPath, b, 0o644)
}

func (s *Spool) readCheckpointLocked(cp *checkpoint) error {
	b, err := os.ReadFile(s.checkpointPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, cp)
}

