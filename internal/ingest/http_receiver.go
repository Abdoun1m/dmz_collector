package ingest

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

func DecodeEventsFromRequest(r *http.Request) ([]event.Event, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	return event.ParseMany(body)
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

