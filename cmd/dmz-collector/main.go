package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/api"
	"github.com/Abdoun1m/dmz_collector/internal/buffer"
	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/forwarder"
	"github.com/Abdoun1m/dmz_collector/internal/ingest"
	"github.com/Abdoun1m/dmz_collector/internal/normalizer"
	"github.com/Abdoun1m/dmz_collector/internal/sourcecatalog"
	"github.com/Abdoun1m/dmz_collector/internal/sourceutil"
	"github.com/Abdoun1m/dmz_collector/internal/stats"
	"github.com/Abdoun1m/dmz_collector/internal/storage"
	"github.com/Abdoun1m/dmz_collector/internal/vault"
)

type App struct {
	cfg    config.Config
	logger *slog.Logger

	store *storage.JSONLStore
	spool *buffer.Spool
	queue *buffer.Queue
	stats *stats.Stats

	streamHub     *api.StreamHub
	fwdStore      *config.ForwardingStore
	sourceCatalog *sourcecatalog.Catalog

	splunkFwd *forwarder.SplunkHECForwarder
	syslogFwd *forwarder.SyslogForwarder

	mu                  sync.RWMutex
	seenIDs             map[string]struct{}
	inflight            map[string]struct{}
	offsetByID          map[string]int64
	splunkSuccessCount  int64
	splunkFailedCount   int64
	splunkLastSuccessAt string
	splunkLastFailureAt string
	splunkLastError     string
	splunkLastEventID   string
	lastHECStatus       string
	lastHECError        string
	failedBatches       int64
	startedAt           string

	sources map[string]config.SourceStatus
}

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	if strings.EqualFold(cfg.StorageBackend, "sqlite") {
		logger.Error("sqlite backend selected but unavailable", "error", storage.ErrSQLiteNotImplemented)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	forwardingStore, err := config.NewForwardingStore(cfg.DataDir+"/forwarding.json", cfg)
	if err != nil {
		logger.Error("failed to init forwarding store", "error", err)
		os.Exit(1)
	}

	app := &App{
		cfg:           cfg,
		logger:        logger,
		store:         storage.NewJSONLStore(cfg.EventsFile),
		spool:         buffer.NewSpool(cfg.SpoolFile),
		queue:         buffer.NewQueue(4096),
		stats:         stats.New(),
		streamHub:     api.NewStreamHub(),
		fwdStore:      forwardingStore,
		sourceCatalog: sourcecatalog.New(cfg.OTBaseURL),
		splunkFwd:     forwarder.NewSplunkHECForwarder(cfg.Splunk.VerifyTLS, 5*time.Second),
		syslogFwd:     forwarder.NewSyslogForwarder(),
		seenIDs:       map[string]struct{}{},
		inflight:      map[string]struct{}{},
		offsetByID:    map[string]int64{},
		startedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		sources:       map[string]config.SourceStatus{},
	}
	app.initSources()
	app.loadSeenIDs()
	app.bootstrapSourceCatalog()
	app.syncOTMetadata(context.Background(), &http.Client{Timeout: 3 * time.Second})
	app.bootstrapSpoolQueue()

	_ = vault.New(cfg.Vault, logger).LoadSecrets()

	go app.runForwardWorker(ctx)
	go app.runOTPull(ctx)
	go app.runOTSSE(ctx)
	go app.runSelfTelemetry(ctx)

	if cfg.EnableFirewallSyslog {
		go func() {
			err := ingest.RunFirewallSyslogUDP(ctx, cfg.FirewallSyslogAddr, logger, func(e event.Event) {
				if err := app.IngestSingle(e); err != nil {
					logger.Warn("failed to ingest firewall syslog event", "error", err)
				}
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("firewall receiver stopped", "error", err)
			}
		}()
	}

	httpAPI := api.New(cfg.APIAddr, cfg.IngestToken, cfg.GDSEventsToken, cfg.OPCUADMZEventsToken, cfg.JumphostEventsToken, app, app.streamHub)
	logger.Info("dmz collector starting", "api", cfg.APIAddr)
	if err := httpAPI.Run(ctx); err != nil {
		logger.Error("api stopped with error", "error", err)
		os.Exit(1)
	}
}

func (a *App) IngestBatch(events []event.Event) (int, int, int, []string) {
	accepted := 0
	rejected := 0
	queued := 0
	errs := make([]string, 0)
	for _, evt := range events {
		ok, wasQueued, err := a.ingestOne(evt)
		if err != nil {
			rejected++
			errs = append(errs, err.Error())
			continue
		}
		if ok {
			accepted++
		}
		if wasQueued {
			queued++
		}
	}
	return accepted, rejected, queued, errs
}

func (a *App) IngestSingle(evt event.Event) error {
	_, _, err := a.ingestOne(evt)
	return err
}

func (a *App) ingestOne(evt event.Event) (bool, bool, error) {
	ev, err := normalizer.ValidateAndNormalize(evt)
	if err != nil {
		return false, false, err
	}
	ev = normalizer.EnrichDMZ(ev)

	a.mu.Lock()
	if _, exists := a.seenIDs[ev.ID]; exists {
		a.mu.Unlock()
		return false, false, nil
	}
	a.seenIDs[ev.ID] = struct{}{}
	a.mu.Unlock()

	if err := a.store.Append(ev); err != nil {
		return false, false, err
	}
	offset, err := a.spool.Append(ev)
	if err != nil {
		return false, false, err
	}

	a.mu.Lock()
	a.offsetByID[ev.ID] = offset
	a.mu.Unlock()

	a.stats.Add(ev)
	a.observeSourceEvent(ev)
	a.streamHub.Publish(ev)
	a.dispatchSplunkForward(ev)

	queued := false
	if a.isForwardingEnabled() {
		queued = a.enqueueIfNeeded(ev, offset)
	}
	return true, queued, nil
}

func (a *App) ReadEvents(q storage.EventQuery) ([]event.Event, error) {
	return a.store.ReadFiltered(q)
}

func (a *App) ReadEventByID(id string) (event.Event, bool, error) {
	return a.store.ReadByID(id)
}

func (a *App) StatsSummary() map[string]any {
	splunk := a.splunkStats()
	return map[string]any{
		"total_events":           a.stats.TotalReceived(),
		"source_count":           a.sourceCatalog.Count(),
		"critical_count":         a.stats.SeverityCount("critical"),
		"warning_count":          a.stats.SeverityCount("warning"),
		"latest_event_timestamp": a.stats.LatestEventTimestamp(),
		"queue":                  a.QueueStatus(),
		"splunk_enabled":         splunk["splunk_enabled"],
		"splunk_hec_url":         splunk["splunk_hec_url"],
		"splunk_success_count":   splunk["splunk_success_count"],
		"splunk_failed_count":    splunk["splunk_failed_count"],
		"splunk_last_success_at": splunk["splunk_last_success_at"],
		"splunk_last_failure_at": splunk["splunk_last_failure_at"],
		"splunk_last_error":      splunk["splunk_last_error"],
		"splunk_last_event_id":   splunk["splunk_last_event_id"],
	}
}

func (a *App) Stats() map[string]any {
	splunk := a.splunkStats()
	return map[string]any{
		"service":                a.cfg.ServiceName,
		"status":                 "ok",
		"storage_backend":        a.cfg.StorageBackend,
		"events_file":            a.cfg.EventsFile,
		"spool_file":             a.cfg.SpoolFile,
		"queue":                  a.QueueStatus(),
		"total_events":           a.stats.TotalReceived(),
		"source_count":           a.sourceCatalog.Count(),
		"latest_event_timestamp": a.stats.LatestEventTimestamp(),
		"splunk_enabled":         splunk["splunk_enabled"],
		"splunk_hec_url":         splunk["splunk_hec_url"],
		"splunk_success_count":   splunk["splunk_success_count"],
		"splunk_failed_count":    splunk["splunk_failed_count"],
		"splunk_last_success_at": splunk["splunk_last_success_at"],
		"splunk_last_failure_at": splunk["splunk_last_failure_at"],
		"splunk_last_error":      splunk["splunk_last_error"],
		"splunk_last_event_id":   splunk["splunk_last_event_id"],
	}
}

func (a *App) StatsTimeline() []map[string]any {
	return a.stats.Timeline()
}

func (a *App) Sources() map[string]any {
	return a.SourcesWithOptions(false, false, false)
}

func (a *App) SourcesWithOptions(includeInternal, includeDisabled, includeDirectSIEM bool) map[string]any {
	a.refreshOTConfiguredSources()
	snap := a.sourceCatalog.Snapshot(sourcecatalog.VisibilityOptions{
		IncludeInternal:   includeInternal,
		IncludeDisabled:   includeDisabled,
		IncludeDirectSIEM: includeDirectSIEM,
	})
	return map[string]any{
		"generated_at":               snap.GeneratedAt,
		"source_of_truth":            snap.SourceOfTruth,
		"ot_collector_url":           snap.OTCollectorURL,
		"visible_sources":            snap.VisibleSources,
		"hidden_sources":             snap.HiddenSources,
		"configured_sources_total":   snap.ConfiguredSourcesTotal,
		"discovered_sources_visible": snap.DiscoveredSourcesVisible,
		"internal_sources_hidden":    snap.InternalSourcesHidden,
		"disabled_sources_hidden":    snap.DisabledSourcesHidden,
		"direct_siem_sources_hidden": snap.DirectSIEMSourcesHidden,
		"total_sources":              snap.TotalSources,
		"configured_sources":         snap.ConfiguredSources,
		"discovered_sources":         snap.DiscoveredSources,
		"sources":                    snap.Sources,
	}
}

func (a *App) SourcesSummary() map[string]any {
	return a.SourcesSummaryWithOptions(false, false, false)
}

func (a *App) SourcesSummaryWithOptions(includeInternal, includeDisabled, includeDirectSIEM bool) map[string]any {
	a.refreshOTConfiguredSources()
	summary := a.sourceCatalog.Summary(sourcecatalog.VisibilityOptions{
		IncludeInternal:   includeInternal,
		IncludeDisabled:   includeDisabled,
		IncludeDirectSIEM: includeDirectSIEM,
	})
	return map[string]any{
		"generated_at":               summary.GeneratedAt,
		"visible_sources":            summary.VisibleSources,
		"hidden_sources":             summary.HiddenSources,
		"configured_sources_total":   summary.ConfiguredSourcesTotal,
		"discovered_sources_visible": summary.DiscoveredSourcesVisible,
		"internal_sources_hidden":    summary.InternalSourcesHidden,
		"disabled_sources_hidden":    summary.DisabledSourcesHidden,
		"direct_siem_sources_hidden": summary.DirectSIEMSourcesHidden,
		"by_group":                   summary.ByGroup,
		"by_source_type":             summary.BySourceType,
		"by_zone":                    summary.ByZone,
		"by_severity":                summary.BySeverity,
		"by_category":                summary.ByCategory,
	}
}

func (a *App) InternalSources() map[string]any {
	a.refreshOTConfiguredSources()
	snap := a.sourceCatalog.Snapshot(sourcecatalog.VisibilityOptions{
		IncludeInternal:   true,
		IncludeDisabled:   true,
		IncludeDirectSIEM: false,
	})
	filtered := make([]sourcecatalog.SourceRecord, 0, len(snap.Sources))
	configured := 0
	discovered := 0
	for _, rec := range snap.Sources {
		if sourceutil.IsInternalDMZSourceType(rec.SourceType) || rec.Group == "DMZ Services" || sourceutil.IsSupportOnlySourceName(rec.Name) {
			filtered = append(filtered, rec)
			if rec.Configured {
				configured++
			}
			if rec.Discovered {
				discovered++
			}
		}
	}
	return map[string]any{
		"generated_at":               snap.GeneratedAt,
		"source_of_truth":            snap.SourceOfTruth,
		"ot_collector_url":           snap.OTCollectorURL,
		"visible_sources":            len(filtered),
		"hidden_sources":             snap.TotalSources - len(filtered),
		"configured_sources_total":   snap.ConfiguredSourcesTotal,
		"discovered_sources_visible": snap.DiscoveredSourcesVisible,
		"internal_sources_hidden":    snap.InternalSourcesHidden,
		"disabled_sources_hidden":    snap.DisabledSourcesHidden,
		"direct_siem_sources_hidden": snap.DirectSIEMSourcesHidden,
		"total_sources":              len(filtered),
		"configured_sources":         configured,
		"discovered_sources":         discovered,
		"sources":                    filtered,
	}
}

func (a *App) SourceDetail(sourceType, assetIP string, limit int) (map[string]any, bool) {
	a.refreshOTConfiguredSources()
	normalizedSourceType := sourceutil.NormalizeSourceType(sourceType)
	detail, ok := a.sourceCatalog.Detail(normalizedSourceType, assetIP, limit)
	if !ok {
		return nil, false
	}
	recent, err := a.store.ReadFiltered(storage.EventQuery{Limit: limit, SourceType: normalizedSourceType, Asset: assetIP})
	if err == nil {
		detail.RecentEvents = make([]map[string]any, 0, len(recent))
		for _, evt := range recent {
			detail.RecentEvents = append(detail.RecentEvents, evt.ToMap())
		}
	}
	return map[string]any{
		"source":        detail.Source,
		"recent_events": detail.RecentEvents,
	}, true
}

func (a *App) refreshOTConfiguredSources() {
	a.sourceCatalog.SeedConfiguredSources(config.DefaultSources())
	if strings.TrimSpace(a.cfg.OTBaseURL) == "" {
		return
	}
	if a.logger != nil {
		a.logger.Info("refreshing OT configured sources", "ot_pull_enabled", a.cfg.EnableOTPull, "ot_collector_url", a.cfg.OTBaseURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.OTBaseURL+"/config/sources", nil)
	if err != nil {
		if a.logger != nil {
			a.logger.Warn("ot_config_sources_fetch_error", "error", err)
		}
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		if a.logger != nil {
			a.logger.Warn("ot_config_sources_fetch_error", "error", err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if a.logger != nil {
			a.logger.Warn("ot_config_sources_fetch_error", "status", resp.Status)
		}
		return
	}
	var rows []sourcecatalog.OTConfiguredSource
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&rows); err != nil {
		if a.logger != nil {
			a.logger.Warn("ot_config_sources_fetch_error", "error", err)
		}
		return
	}
	if a.logger != nil {
		a.logger.Info("ot_config_sources_count", "ot_config_sources_count", len(rows))
	}
	a.sourceCatalog.MergeConfiguredSources(rows)
	a.sourceCatalog.SetOTURL(a.cfg.OTBaseURL)
	snap := a.sourceCatalog.Snapshot(sourcecatalog.VisibilityOptions{IncludeInternal: true, IncludeDisabled: true, IncludeDirectSIEM: true})
	if a.logger != nil {
		a.logger.Info("source merge result", "source_merge_configured_count", snap.ConfiguredSources, "source_merge_discovered_count", snap.DiscoveredSources)
	}
}

func (a *App) ForwardingStatus() config.ForwardingStatus {
	q := a.queue.Snapshot()
	a.mu.RLock()
	defer a.mu.RUnlock()
	return config.ForwardingStatus{
		Queued:       q.Queued,
		Forwarded:    q.Forwarded,
		Failed:       q.Failed,
		LastSuccess:  q.LastSuccess,
		LastFailure:  q.LastFailure,
		LastResponse: firstNonEmpty(a.lastHECStatus, a.lastHECError),
	}
}

func (a *App) ForwardingConfig() config.ForwardingConfig {
	return a.fwdStore.Get()
}

func (a *App) UpdateForwardingConfig(cfg config.ForwardingConfig) error {
	if err := a.fwdStore.Replace(cfg); err != nil {
		return err
	}
	a.queue.SetPaused(cfg.Paused)
	if !cfg.Paused && (cfg.SplunkEnabled || cfg.SyslogForwardEnabled) {
		a.enqueuePendingFromSpool()
	}
	return nil
}

func (a *App) TestForwarding() (map[string]any, error) {
	cfg := a.fwdStore.Get()
	test := event.Event{
		ID:            "dmz-forwarding-test",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Zone:          "OT",
		SourceType:    "unknown",
		AssetName:     "dmz_collector",
		AssetIP:       "192.168.10.70",
		Severity:      "info",
		Protocol:      "http",
		EventCategory: "system",
		Message:       "dmz forwarding test",
		Raw:           "{}",
		Tags:          map[string]any{},
	}
	test = normalizer.EnrichDMZ(test)
	if err := a.forwardBatch([]event.Event{test}, cfg); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "status": a.lastHECStatus}, nil
}

func (a *App) TestSplunk() (map[string]any, error) {
	cfg := a.cfg.Splunk
	if !cfg.Enabled {
		return map[string]any{
			"status":          "failed",
			"http_status":     0,
			"splunk_response": "",
			"error":           "splunk hec is disabled",
		}, nil
	}
	test := event.Event{
		ID:            "dmz-splunk-test",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Zone:          "DMZ",
		Source:        cfg.Source,
		SourceType:    "gds-agent",
		AssetName:     "dmz_collector",
		AssetIP:       "192.168.10.70",
		Severity:      "info",
		Protocol:      "http",
		EventCategory: "system",
		Message:       "dmz splunk hec test",
		Raw:           "{}",
		Tags:          map[string]any{},
	}
	test = normalizer.EnrichDMZ(test)
	result, err := a.splunkForwarder().Send(cfg.URL, cfg.Token, cfg.Source, cfg.Index, test)
	if err != nil {
		return map[string]any{
			"status":          "failed",
			"http_status":     result.StatusCode,
			"splunk_response": result.Body,
			"error":           err.Error(),
		}, nil
	}
	return map[string]any{
		"status":          "ok",
		"http_status":     result.StatusCode,
		"splunk_response": result.Body,
		"error":           "",
	}, nil
}

func (a *App) FlushForwarding() map[string]any {
	n := a.enqueuePendingFromSpool()
	return map[string]any{"ok": true, "enqueued": n}
}

func (a *App) QueueStatus() map[string]any {
	q := a.queue.Snapshot()
	return map[string]any{
		"queued":       q.Queued,
		"forwarded":    q.Forwarded,
		"failed":       q.Failed,
		"last_success": q.LastSuccess,
		"last_failure": q.LastFailure,
		"paused":       q.Paused,
		"events_file":  a.cfg.EventsFile,
		"spool_file":   a.cfg.SpoolFile,
	}
}

func (a *App) Health() map[string]any {
	return map[string]any{
		"status":          "ok",
		"service":         a.cfg.ServiceName,
		"api_addr":        a.cfg.APIAddr,
		"storage_backend": a.cfg.StorageBackend,
		"events_file":     a.cfg.EventsFile,
		"spool_file":      a.cfg.SpoolFile,
		"started_at":      a.startedAt,
		"queue":           a.QueueStatus(),
	}
}

func (a *App) runForwardWorker(ctx context.Context) {
	var pending []event.Event
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cfg := a.fwdStore.Get()
		a.queue.SetPaused(cfg.Paused)
		if pending == nil {
			pending = a.queue.PopBatch(a.cfg.QueueBatchSize, 1*time.Second)
			if len(pending) == 0 {
				continue
			}
		}

		if cfg.Paused || !cfg.SyslogForwardEnabled {
			time.Sleep(1 * time.Second)
			continue
		}

		// Prioritize high-value records in every batch.
		sort.SliceStable(pending, func(i, j int) bool {
			return highValue(pending[i]) && !highValue(pending[j])
		})

		if err := a.forwardBatch(pending, cfg); err != nil {
			a.queue.MarkFailure(len(pending), time.Now().UTC().Format(time.RFC3339Nano))
			a.mu.Lock()
			a.failedBatches++
			a.lastHECError = err.Error()
			a.mu.Unlock()
			attempt++
			time.Sleep(forwarder.Backoff(attempt))
			continue
		}

		when := time.Now().UTC().Format(time.RFC3339Nano)
		a.queue.MarkSuccess(len(pending), when)
		a.markBatchForwarded(pending)
		a.forgetInflight(pending)
		pending = nil
		attempt = 0
		_ = a.enqueuePendingFromSpool()
	}
}

func (a *App) forwardBatch(batch []event.Event, cfg config.ForwardingConfig) error {
	if cfg.SyslogForwardEnabled {
		for _, e := range batch {
			if err := a.syslogFwd.Send(cfg.SyslogForwardHost, cfg.SyslogForwardPort, cfg.SyslogForwardProtocol, e); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) runOTPull(ctx context.Context) {
	if !a.cfg.EnableOTPull {
		return
	}
	client := &http.Client{Timeout: 3 * time.Second}
	tick := time.NewTicker(a.cfg.OTPollEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.syncOTMetadata(ctx, client)
			reqURL := a.cfg.OTBaseURL + "/events?limit=" + strconv.Itoa(a.cfg.OTEventLimit)
			resp, err := client.Get(reqURL)
			if err != nil {
				a.markSourceSeen("ot_collector", false)
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
			_ = resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				a.markSourceSeen("ot_collector", false)
				continue
			}
			var rows []map[string]any
			if err := json.Unmarshal(body, &rows); err != nil {
				a.markSourceSeen("ot_collector", false)
				continue
			}
			for _, row := range rows {
				b, _ := json.Marshal(row)
				ev, err := event.ParseOne(b)
				if err != nil {
					continue
				}
				a.observeSourceEvent(ev)
				_, _, _ = a.ingestOne(ev)
			}
			a.markSourceSeen("ot_collector", true)
		}
	}
}

func (a *App) runOTSSE(ctx context.Context) {
	if !a.cfg.EnableOTSSE {
		return
	}
	client := &http.Client{}
	backoff := 1 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.OTBaseURL+"/events/stream", nil)
		req.Header.Set("Accept", "text/event-stream")
		resp, err := client.Do(req)
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			time.Sleep(backoff)
			if backoff < 20*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 1 * time.Second
		a.markSourceSeen("ot_collector", true)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			raw := strings.TrimPrefix(line, "data: ")
			ev, err := event.ParseOne([]byte(raw))
			if err != nil {
				continue
			}
			a.observeSourceEvent(ev)
			_, _, _ = a.ingestOne(ev)
		}
		_ = resp.Body.Close()
	}
}

func (a *App) runSelfTelemetry(ctx context.Context) {
	cfg := a.cfg.SelfTelemetry
	if !cfg.Enabled {
		return
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	_ = a.emitSelfTelemetry("dmz_collector_started", "info", "system_health", map[string]any{
		"queue_depth":       a.queueDepth(),
		"spool_event_count": a.queueDepth(),
		"started_at":        a.startedAt,
	})

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	var lastTotal int64
	var lastForwarded int64
	var lastFailed int64
	var hecWasFailed bool
	for {
		select {
		case <-ctx.Done():
			_ = a.emitSelfTelemetry("dmz_collector_heartbeat", "info", "system_health", map[string]any{"status": "shutdown"})
			return
		case <-ticker.C:
			q := a.queueStats()
			total := a.stats.TotalReceived()
			splunk := a.splunkStats()
			splunkSuccesses := int64FromAny(splunk["splunk_success_count"])
			splunkFailures := int64FromAny(splunk["splunk_failed_count"])
			raw := map[string]any{
				"events_received":   total,
				"events_forwarded":  splunkSuccesses,
				"events_dropped":    q.Failed,
				"spool_event_count": q.Queued,
				"queue_depth":       q.Queued,
				"hec_url":           splunk["splunk_hec_url"],
				"hec_error":         splunk["splunk_last_error"],
				"splunk_successes":  splunkSuccesses,
				"splunk_failures":   splunkFailures,
				"last_success_at":   splunk["splunk_last_success_at"],
				"last_failure_at":   splunk["splunk_last_failure_at"],
				"latest_event_time": a.stats.LatestEventTimestamp(),
			}
			_ = a.emitSelfTelemetry("dmz_collector_heartbeat", "info", "system_health", raw)
			if cfg.EmitEventFlowCounters && total > lastTotal {
				raw["events_received_delta"] = total - lastTotal
				_ = a.emitSelfTelemetry("dmz_collector_event_received", "info", "data_collection", raw)
			}
			if cfg.EmitEventFlowCounters && splunkSuccesses > lastForwarded {
				raw["events_forwarded_delta"] = splunkSuccesses - lastForwarded
				_ = a.emitSelfTelemetry("dmz_collector_event_forwarded", "info", "data_collection", raw)
			}
			if splunkFailures > lastFailed {
				_ = a.emitSelfTelemetry("dmz_collector_hec_failure", "critical", "error", raw)
				hecWasFailed = true
			} else if hecWasFailed && splunkFailures == lastFailed && splunkSuccesses > lastForwarded {
				_ = a.emitSelfTelemetry("dmz_collector_hec_recovered", "info", "system_health", raw)
				hecWasFailed = false
			}
			if q.Queued >= cfg.SpoolCriticalEvents {
				_ = a.emitSelfTelemetry("dmz_collector_spool_overflow", "critical", "error", raw)
			} else if q.Queued >= cfg.SpoolWarnEvents {
				_ = a.emitSelfTelemetry("dmz_collector_spool_growing", "warning", "system_health", raw)
			}
			lastTotal = a.stats.TotalReceived()
			lastForwarded = int64FromAny(a.splunkStats()["splunk_success_count"])
			lastFailed = int64FromAny(a.splunkStats()["splunk_failed_count"])
		}
	}
}

func (a *App) emitSelfTelemetry(message, severity, category string, raw map[string]any) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rawJSON, _ := json.Marshal(raw)
	risk := "LOW"
	if severity == "critical" {
		risk = "CRITICAL"
	} else if severity == "warning" || severity == "error" {
		risk = "HIGH"
	}
	tags := map[string]any{
		"component":               "dmz_collector",
		"zone":                    "DMZ",
		"collector_decision_hint": "sample_or_drop",
		"risk_level":              risk,
		"normalized":              true,
		"normalization_source":    "logs_by_sources_md",
		"parser_version":          "v2.logs_by_sources_md",
		"splunk_sourcetype":       "labshock:dmz:dmz_collector",
		"siem_index_hint":         "ot_security",
	}
	if isSelfTelemetryProtected(message) {
		tags["alert_candidate"] = true
		tags["collector_decision_hint"] = "store_forward"
	}
	for k, v := range raw {
		if _, exists := tags[k]; !exists {
			tags[k] = v
		}
	}
	ev := event.Event{
		Timestamp:     now,
		ReceivedAt:    now,
		Zone:          "DMZ",
		Source:        "labshock_dmz_collector",
		SourceType:    "dmz_collector",
		AssetName:     "DMZ Collector",
		AssetIP:       "192.168.10.70",
		Severity:      severity,
		Protocol:      "self_telemetry",
		EventCategory: category,
		Message:       message,
		Raw:           string(rawJSON),
		Tags:          tags,
	}
	return a.IngestSingle(ev)
}

func isSelfTelemetryProtected(message string) bool {
	switch message {
	case "dmz_collector_hec_failure", "dmz_collector_spool_overflow", "dmz_collector_normalization_gap":
		return true
	default:
		return false
	}
}

func (a *App) queueStats() buffer.QueueStats {
	if a.queue == nil {
		return buffer.QueueStats{}
	}
	return a.queue.Snapshot()
}

func (a *App) queueDepth() int64 {
	return a.queueStats().Queued
}

func int64FromAny(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	default:
		return 0
	}
}

func (a *App) enqueuePendingFromSpool() int {
	records, err := a.spool.LoadPending()
	if err != nil {
		a.logger.Warn("failed loading spool records", "error", err)
		return 0
	}
	count := 0
	for _, rec := range records {
		if a.enqueueIfNeeded(rec.Event, rec.Offset) {
			count++
		}
	}
	return count
}

func (a *App) enqueueIfNeeded(ev event.Event, offset int64) bool {
	a.mu.Lock()
	if _, exists := a.inflight[ev.ID]; exists {
		a.mu.Unlock()
		return false
	}
	a.mu.Unlock()
	if !a.queue.Push(ev) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inflight[ev.ID] = struct{}{}
	a.offsetByID[ev.ID] = offset
	return true
}

func (a *App) markBatchForwarded(batch []event.Event) {
	var maxOffset int64
	found := false
	a.mu.RLock()
	for _, e := range batch {
		if off, ok := a.offsetByID[e.ID]; ok {
			if !found || off > maxOffset {
				maxOffset = off
				found = true
			}
		}
	}
	a.mu.RUnlock()
	if found {
		_ = a.spool.MarkForwarded(maxOffset)
	}
}

func (a *App) forgetInflight(batch []event.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range batch {
		delete(a.inflight, e.ID)
	}
}

func (a *App) isForwardingEnabled() bool {
	cfg := a.fwdStore.Get()
	return !cfg.Paused && cfg.SyslogForwardEnabled
}

func (a *App) loadSeenIDs() {
	ids, err := a.store.LoadIDSet()
	if err != nil {
		a.logger.Warn("failed loading id set", "error", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seenIDs = ids
}

func (a *App) bootstrapSpoolQueue() {
	if !a.isForwardingEnabled() {
		return
	}
	n := a.enqueuePendingFromSpool()
	if n > 0 {
		a.logger.Info("pending spool records loaded", "count", n)
	}
}

func (a *App) initSources() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sources == nil {
		a.sources = map[string]config.SourceStatus{}
	}
	for _, s := range config.DefaultSources() {
		a.sources[s.Type] = s
	}
	a.sourceCatalog.SeedConfiguredSources(config.DefaultSources())
}

func (a *App) bootstrapSourceCatalog() {
	events, err := a.store.LoadAll()
	if err != nil {
		a.logger.Warn("failed loading stored events for source bootstrap", "error", err)
		return
	}
	a.sourceCatalog.BootstrapEvents(events)
}

func (a *App) updateSourceFromEvent(e event.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := e.SourceType
	src := a.sources[key]
	if src.Name == "" {
		src = config.SourceStatus{Name: strings.ToUpper(e.SourceType), Type: e.SourceType, Endpoint: e.AssetIP, Enabled: true}
	}
	src.LastSeen = time.Now().UTC().Format(time.RFC3339Nano)
	src.EventSeen++
	if src.Endpoint == "" {
		src.Endpoint = e.AssetIP
	}
	a.sources[key] = src
}

func (a *App) splunkStats() map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return map[string]any{
		"splunk_enabled":         a.cfg.Splunk.Enabled,
		"splunk_hec_url":         a.cfg.Splunk.URL,
		"splunk_success_count":   a.splunkSuccessCount,
		"splunk_failed_count":    a.splunkFailedCount,
		"splunk_last_success_at": a.splunkLastSuccessAt,
		"splunk_last_failure_at": a.splunkLastFailureAt,
		"splunk_last_error":      a.splunkLastError,
		"splunk_last_event_id":   a.splunkLastEventID,
	}
}

func (a *App) dispatchSplunkForward(ev event.Event) {
	if !a.cfg.Splunk.Enabled {
		return
	}
	go a.forwardSplunkAsync(ev)
}

func (a *App) forwardSplunkAsync(ev event.Event) {
	cfg := a.cfg.Splunk
	payload := event.BuildSplunkPayload(ev, cfg.Source, cfg.Index)
	start := time.Now()
	result, err := a.splunkForwarder().Send(cfg.URL, cfg.Token, cfg.Source, cfg.Index, ev)
	elapsed := time.Since(start).Milliseconds()
	success := err == nil
	a.recordSplunkAttempt(ev.ID, success, result.StatusCode, result.Body, err)
	if a.logger == nil {
		return
	}
	fields := []any{
		"event_id", ev.ID,
		"source_type", ev.SourceType,
		"splunk_enabled", cfg.Enabled,
		"splunk_hec_url", cfg.URL,
		"splunk_index", cfg.Index,
		"splunk_sourcetype", payload.Sourcetype,
		"splunk_attempted", true,
		"splunk_success", success,
		"http_status", result.StatusCode,
		"error", err,
		"elapsed_ms", elapsed,
	}
	if success {
		a.logger.Info("splunk_hec_forward", fields...)
		return
	}
	a.logger.Warn("splunk_hec_forward", fields...)
}

func (a *App) recordSplunkAttempt(eventID string, success bool, httpStatus int, responseBody string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.splunkLastEventID = eventID
	if success {
		a.splunkSuccessCount++
		a.splunkLastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
		a.splunkLastError = ""
		return
	}
	a.splunkFailedCount++
	a.splunkLastFailureAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		a.splunkLastError = err.Error()
		return
	}
	if responseBody != "" {
		a.splunkLastError = responseBody
		return
	}
	if httpStatus > 0 {
		a.splunkLastError = "splunk status " + strconv.Itoa(httpStatus)
	}
}

func (a *App) splunkForwarder() *forwarder.SplunkHECForwarder {
	if a.splunkFwd != nil {
		return a.splunkFwd
	}
	return forwarder.NewSplunkHECForwarder(a.cfg.Splunk.VerifyTLS, 5*time.Second)
}

func (a *App) observeSourceEvent(e event.Event) {
	a.sourceCatalog.ObserveEvent(e)
}

func (a *App) syncOTMetadata(ctx context.Context, client *http.Client) {
	endpoints := []string{"/config/sources", "/stats", "/config/rules", "/config/forwarding"}
	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.OTBaseURL+endpoint, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			a.logger.Debug("ot metadata sync failed", "endpoint", endpoint, "error", err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			a.logger.Debug("ot metadata sync non-2xx", "endpoint", endpoint, "status", resp.Status)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.OTBaseURL+"/config/sources", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return
	}
	var rows []sourcecatalog.OTConfiguredSource
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&rows); err != nil {
		a.logger.Debug("failed decoding ot config sources", "error", err)
		return
	}
	a.sourceCatalog.MergeConfiguredSources(rows)
	a.sourceCatalog.SetOTURL(a.cfg.OTBaseURL)
}

func (a *App) markSourceSeen(kind string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	src := a.sources[kind]
	if src.Name == "" {
		return
	}
	if ok {
		src.LastSeen = time.Now().UTC().Format(time.RFC3339Nano)
	}
	a.sources[kind] = src
}

func highValue(e event.Event) bool {
	if v, ok := e.Tags["high_value"].(bool); ok {
		return v
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}
