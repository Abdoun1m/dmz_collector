package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/auth"
	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/ingest"
	"github.com/Abdoun1m/dmz_collector/internal/storage"
)

func (a *API) handleHealth(w http.ResponseWriter, _ *http.Request) {
	ingest.WriteJSON(w, http.StatusOK, a.core.Health())
}

func (a *API) handleEventsIngestOrList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		auth.RequireBearer(a.ingestToken, a.handleEventsIngest)(w, r)
	case http.MethodGet:
		a.handleEventsList(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleEventsIngest(w http.ResponseWriter, r *http.Request) {
	events, err := ingest.DecodeEventsFromRequest(r)
	if err != nil {
		ingest.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"accepted": 0, "rejected": 1, "queued": 0, "errors": []string{"invalid json payload"},
		})
		return
	}
	accepted, rejected, queued, errs := a.core.IngestBatch(events)
	ingest.WriteJSON(w, http.StatusAccepted, map[string]any{
		"accepted": accepted,
		"rejected": rejected,
		"queued":   queued,
		"errors":   errs,
	})
}

func (a *API) handleEventsList(w http.ResponseWriter, r *http.Request) {
	q := storage.EventQuery{
		Limit:      parseInt(r.URL.Query().Get("limit"), 200),
		SourceType: strings.TrimSpace(r.URL.Query().Get("source_type")),
		Severity:   strings.TrimSpace(r.URL.Query().Get("severity")),
		Category:   strings.TrimSpace(r.URL.Query().Get("category")),
		Asset:      strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("asset"), r.URL.Query().Get("asset_ip"))),
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
	}
	list, err := a.core.ReadEvents(q)
	if err != nil {
		http.Error(w, "failed to read events", http.StatusInternalServerError)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, list)
}

func (a *API) handleEventByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/events/stream") {
		a.handleEventStream(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/events/")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	evt, ok, err := a.core.ReadEventByID(id)
	if err != nil {
		http.Error(w, "failed to read event", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, evt)
}

func (a *API) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, a.core.StatsSummary())
}

func (a *API) handleStatsTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, a.core.StatsTimeline())
}

func (a *API) handleSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, a.core.Sources())
}

func (a *API) handleForwardingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, a.core.ForwardingStatus())
}

func (a *API) handleConfigForwarding(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ingest.WriteJSON(w, http.StatusOK, a.core.ForwardingConfig())
	case http.MethodPost:
		defer r.Body.Close()
		var cfg config.ForwardingConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&cfg); err != nil {
			http.Error(w, "invalid forwarding config", http.StatusBadRequest)
			return
		}
		if err := a.core.UpdateForwardingConfig(cfg); err != nil {
			http.Error(w, fmt.Sprintf("update failed: %v", err), http.StatusInternalServerError)
			return
		}
		ingest.WriteJSON(w, http.StatusOK, a.core.ForwardingConfig())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleForwardingTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result, err := a.core.TestForwarding()
	if err != nil {
		ingest.WriteJSON(w, http.StatusBadGateway, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	ingest.WriteJSON(w, http.StatusOK, result)
}

func (a *API) handleForwardingFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, a.core.FlushForwarding())
}

func (a *API) handleQueueStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ingest.WriteJSON(w, http.StatusOK, a.core.QueueStatus())
}

func (a *API) handleIDSAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ev, err := ingest.NormalizeIDSAlert(body)
	if err != nil {
		http.Error(w, "invalid ids payload", http.StatusBadRequest)
		return
	}
	if err := a.core.IngestSingle(ev); err != nil {
		http.Error(w, "ingest failed", http.StatusInternalServerError)
		return
	}
	ingest.WriteJSON(w, http.StatusAccepted, map[string]any{"accepted": 1, "rejected": 0, "queued": 1, "errors": []string{}})
}

func (a *API) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	id, ch := a.streamHub.Subscribe()
	defer a.streamHub.Unsubscribe(id)

	fmt.Fprintf(w, "event: ready\ndata: {\"status\":\"connected\"}\n\n")
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case evt, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(evt.ToMap())
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: event\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func parseInt(v string, def int) int {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

