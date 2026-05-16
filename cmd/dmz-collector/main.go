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

	streamHub *api.StreamHub
	fwdStore  *config.ForwardingStore
	sourceCatalog *sourcecatalog.Catalog

	splunkFwd *forwarder.SplunkHECForwarder
	syslogFwd *forwarder.SyslogForwarder

	mu            sync.RWMutex
	seenIDs       map[string]struct{}
	inflight      map[string]struct{}
	offsetByID    map[string]int64
	lastHECStatus string
	lastHECError  string
	failedBatches int64
	startedAt     string

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
		cfg:       cfg,
		logger:    logger,
		store:     storage.NewJSONLStore(cfg.EventsFile),
		spool:     buffer.NewSpool(cfg.SpoolFile),
		queue:     buffer.NewQueue(4096),
		stats:     stats.New(),
		streamHub: api.NewStreamHub(),
		fwdStore:  forwardingStore,
		sourceCatalog: sourcecatalog.New(cfg.OTBaseURL),
		splunkFwd: forwarder.NewSplunkHECForwarder(cfg.Splunk.VerifyTLS, 5*time.Second),
		syslogFwd: forwarder.NewSyslogForwarder(),
		seenIDs:   map[string]struct{}{},
		inflight:  map[string]struct{}{},
		offsetByID: map[string]int64{},
		startedAt: time.Now().UTC().Format(time.RFC3339Nano),
		sources:   map[string]config.SourceStatus{},
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

	httpAPI := api.New(cfg.APIAddr, cfg.IngestToken, app, app.streamHub)
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
	return map[string]any{
		"total_events":            a.stats.TotalReceived(),
		"source_count":            a.sourceCatalog.Count(),
		"critical_count":          a.stats.SeverityCount("critical"),
		"warning_count":           a.stats.SeverityCount("warning"),
		"latest_event_timestamp":  a.stats.LatestEventTimestamp(),
		"queue":                   a.QueueStatus(),
	}
}

func (a *App) Stats() map[string]any {
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
		"generated_at":                 snap.GeneratedAt,
		"source_of_truth":              snap.SourceOfTruth,
		"ot_collector_url":             snap.OTCollectorURL,
		"visible_sources":              snap.VisibleSources,
		"hidden_sources":               snap.HiddenSources,
		"configured_sources_total":     snap.ConfiguredSourcesTotal,
		"discovered_sources_visible":    snap.DiscoveredSourcesVisible,
		"internal_sources_hidden":       snap.InternalSourcesHidden,
		"disabled_sources_hidden":       snap.DisabledSourcesHidden,
		"direct_siem_sources_hidden":    snap.DirectSIEMSourcesHidden,
		"total_sources":                snap.TotalSources,
		"configured_sources":           snap.ConfiguredSources,
		"discovered_sources":           snap.DiscoveredSources,
		"sources":                      snap.Sources,
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
		"generated_at":                 summary.GeneratedAt,
		"visible_sources":              summary.VisibleSources,
		"hidden_sources":               summary.HiddenSources,
		"configured_sources_total":     summary.ConfiguredSourcesTotal,
		"discovered_sources_visible":    summary.DiscoveredSourcesVisible,
		"internal_sources_hidden":       summary.InternalSourcesHidden,
		"disabled_sources_hidden":       summary.DisabledSourcesHidden,
		"direct_siem_sources_hidden":    summary.DirectSIEMSourcesHidden,
		"by_group":                     summary.ByGroup,
		"by_source_type":               summary.BySourceType,
		"by_zone":                      summary.ByZone,
		"by_severity":                  summary.BySeverity,
		"by_category":                  summary.ByCategory,
	}
}

func (a *App) InternalSources() map[string]any {
	return a.SourcesWithOptions(true, true, true)
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
	if strings.TrimSpace(a.cfg.OTBaseURL) == "" {
		return
	}
	a.logger.Info("refreshing OT configured sources", "ot_pull_enabled", a.cfg.EnableOTPull, "ot_collector_url", a.cfg.OTBaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.OTBaseURL+"/config/sources", nil)
	if err != nil {
		a.logger.Warn("ot_config_sources_fetch_error", "error", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		a.logger.Warn("ot_config_sources_fetch_error", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		a.logger.Warn("ot_config_sources_fetch_error", "status", resp.Status)
		return
	}
	var rows []sourcecatalog.OTConfiguredSource
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&rows); err != nil {
		a.logger.Warn("ot_config_sources_fetch_error", "error", err)
		return
	}
	a.logger.Info("ot_config_sources_count", "ot_config_sources_count", len(rows))
	a.sourceCatalog.MergeConfiguredSources(rows)
	a.sourceCatalog.SetOTURL(a.cfg.OTBaseURL)
	snap := a.sourceCatalog.Snapshot()
	a.logger.Info("source merge result", "source_merge_configured_count", snap.ConfiguredSources, "source_merge_discovered_count", snap.DiscoveredSources)
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

		if cfg.Paused || (!cfg.SplunkEnabled && !cfg.SyslogForwardEnabled) {
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
	if cfg.SplunkEnabled {
		status, err := a.splunkFwd.SendBatch(cfg.SplunkHECURL, cfg.SplunkHECToken, cfg.SplunkSource, cfg.SplunkIndex, batch)
		a.mu.Lock()
		a.lastHECStatus = status
		a.lastHECError = ""
		a.mu.Unlock()
		if err != nil {
			return err
		}
	}
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
	return !cfg.Paused && (cfg.SplunkEnabled || cfg.SyslogForwardEnabled)
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
