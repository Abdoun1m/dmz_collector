package api

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/auth"
	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/storage"
	webassets "github.com/Abdoun1m/dmz_collector/web"
)

type Core interface {
	IngestBatch([]event.Event) (int, int, int, []string)
	IngestSingle(event.Event) error
	ReadEvents(storage.EventQuery) ([]event.Event, error)
	ReadEventByID(string) (event.Event, bool, error)
	Stats() map[string]any
	StatsSummary() map[string]any
	StatsTimeline() []map[string]any
	Sources() map[string]any
	SourcesWithOptions(bool, bool, bool) map[string]any
	SourcesSummary() map[string]any
	SourcesSummaryWithOptions(bool, bool, bool) map[string]any
	InternalSources() map[string]any
	SourceDetail(string, string, int) (map[string]any, bool)
	ForwardingStatus() config.ForwardingStatus
	ForwardingConfig() config.ForwardingConfig
	UpdateForwardingConfig(config.ForwardingConfig) error
	TestForwarding() (map[string]any, error)
	TestSplunk() (map[string]any, error)
	FlushForwarding() map[string]any
	QueueStatus() map[string]any
	Health() map[string]any
}

type API struct {
	addr        string
	ingestToken string
	core        Core
	streamHub   *StreamHub
}

func New(addr string, ingestToken string, core Core, streamHub *StreamHub) *API {
	return &API{
		addr:        addr,
		ingestToken: ingestToken,
		core:        core,
		streamHub:   streamHub,
	}
}

func (a *API) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/events", a.handleEventsIngestOrList)
	mux.HandleFunc("/events/", a.handleEventByID)
	mux.HandleFunc("/events/stream", a.handleEventStream)
	mux.HandleFunc("/stats", a.handleStatsSummary)
	mux.HandleFunc("/stats/summary", a.handleStatsSummary)
	mux.HandleFunc("/stats/timeline", a.handleStatsTimeline)
	mux.HandleFunc("/sources", a.handleSources)
	mux.HandleFunc("/sources/summary", a.handleSourcesSummary)
	mux.HandleFunc("/sources/detail", a.handleSourceDetail)
	mux.HandleFunc("/internal/sources", a.handleInternalSources)
	mux.HandleFunc("/forwarding/status", a.handleForwardingStatus)
	mux.HandleFunc("/config/forwarding", a.handleConfigForwarding)
	mux.HandleFunc("/config/rules", a.handleConfigRules)
	mux.HandleFunc("/filter/config", a.handleFilterConfig)
	mux.HandleFunc("/forwarding/test", a.handleForwardingTest)
	mux.HandleFunc("/splunk/test", a.handleSplunkTest)
	mux.HandleFunc("/forwarding/flush", a.handleForwardingFlush)
	mux.HandleFunc("/queue/status", a.handleQueueStatus)
	mux.HandleFunc("/ids/alerts", auth.RequireBearer(a.ingestToken, a.handleIDSAlerts))
	mux.HandleFunc("/vault/audit", auth.RequireBearer(a.ingestToken, a.handleVaultAudit))
	mux.HandleFunc("/gds/events", auth.RequireBearer(a.ingestToken, a.handleGDSEvents))

	sub, err := fs.Sub(webassets.FS, ".")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}

	s := &http.Server{
		Addr:              a.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", a.addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shutdownCtx)
	}()
	err = s.Serve(ln)
	if err == nil || err == http.ErrServerClosed {
		return nil
	}
	return err
}
