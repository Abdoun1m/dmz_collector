package ingest

import (
	"encoding/json"
	"io"
	"net/http"
	"errors"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

func DecodeEventsFromRequest(r *http.Request) ([]event.Event, error) {
	defer r.Body.Close()
	const limit = 4 * 1024 * 1024
	if r.ContentLength > limit {
		return nil, ErrPayloadTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, err
		}
		return nil, err
	}
	return event.ParseMany(body)
}

var ErrPayloadTooLarge = errors.New("payload too large")

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

