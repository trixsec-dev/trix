package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

type Server struct {
	config    *Config
	db        *DB
	poller    *Poller
	notifier  *Notifier
	logger    *slog.Logger
	ready     atomic.Bool
	firstPoll bool
}

func New(config *Config, logger *slog.Logger) (*Server, error) {
	ctx := context.Background()

	db, err := NewDB(ctx, config.DatabaseURL)
	if err != nil {
		return nil, err
	}

	poller, err := NewPoller(db, config, logger)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	notifier := NewNotifier(config, logger)

	return &Server{
		config:    config,
		db:        db,
		poller:    poller,
		notifier:  notifier,
		logger:    logger,
		firstPoll: true,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go s.runHealthServer(ctx)
	go s.runPollLoop(ctx)

	select {
	case sig := <-sigCh:
		s.logger.Info("received signal, shutting down", "signal", sig)
	case <-ctx.Done():
	}

	cancel()
	_ = s.db.Close()
	return nil
}

func (s *Server) runHealthServer(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
		}
	})

	srv := &http.Server{
		Addr:    s.config.HealthAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.logger.Info("health server starting", "addr", s.config.HealthAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		s.logger.Error("health server error", "error", err)
	}
}

func (s *Server) runPollLoop(ctx context.Context) {
	s.logger.Info("starting poll loop", "interval", s.config.PollInterval)

	// Initial poll
	s.poll(ctx)
	s.ready.Store(true)

	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

func (s *Server) poll(ctx context.Context) {
	events, err := s.poller.Poll(ctx)
	if err != nil {
		s.logger.Error("poll failed", "error", err)
		return
	}

	if !s.config.HasNotifications() {
		return
	}

	// Always check for unsynced events and retry them
	if s.config.SaasEndpoint != "" {
		s.retrySaasSync(ctx)
	}

	if s.firstPoll {
		s.firstPoll = false
		// Only send init notification on fresh start (new vulnerabilities found)
		// Skip if this is a restart with existing database
		if len(events) > 0 {
			result := s.notifier.NotifyInitialized(ctx, events)
			s.handleSaasResult(ctx, result)
		} else {
			s.logger.Info("resumed monitoring, database has existing data")
		}
		return
	}

	if len(events) > 0 {
		result := s.notifier.Notify(ctx, events)
		s.handleSaasResult(ctx, result)
	}
}

// handleSaasResult marks synced events in the database.
func (s *Server) handleSaasResult(ctx context.Context, result *SaasResult) {
	if result == nil {
		return
	}

	if len(result.SyncedIDs) > 0 {
		if err := s.db.MarkSaasSynced(ctx, result.SyncedIDs); err != nil {
			s.logger.Error("failed to mark events as synced", "error", err)
		}
	}

	if result.Err != nil {
		s.logger.Error("saas sync had failures",
			"synced", len(result.SyncedIDs),
			"failed", len(result.FailedIDs),
			"error", result.Err,
		)
	} else if len(result.SyncedIDs) > 0 {
		s.logger.Info("saas sync complete", "synced", len(result.SyncedIDs))
	}
}

// retrySaasSync retries syncing events that previously failed.
func (s *Server) retrySaasSync(ctx context.Context) {
	unsynced, err := s.db.GetUnsyncedVulnerabilities(ctx)
	if err != nil {
		s.logger.Error("failed to get unsynced vulnerabilities", "error", err)
		return
	}

	if len(unsynced) == 0 {
		return
	}

	s.logger.Info("retrying unsynced events", "count", len(unsynced))

	// Convert records to events
	events := make([]VulnerabilityEvent, 0, len(unsynced))
	for _, v := range unsynced {
		eventType := "NEW"
		if v.State == StateFixed {
			eventType = "FIXED"
		}
		events = append(events, VulnerabilityEvent{
			ID:        v.ID,
			Type:      eventType,
			CVE:       v.CVE,
			Workload:  v.Workload,
			Severity:  v.Severity,
			Image:     v.Image,
			FirstSeen: v.FirstSeen,
			FixedAt:   v.FixedAt,
		})
	}

	result := s.notifier.SendSaas(ctx, events)
	s.handleSaasResult(ctx, result)
}
