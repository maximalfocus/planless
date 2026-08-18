// Command controlplane runs the democloud control plane: a fictional platform
// that holds the demonstration's resources and authorizes every request against
// the permissions those resources produce.
//
// It is not an emulator of any real cloud provider, contacts nothing outside
// its own container network, and holds no credential of any kind.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maximalfocus/planless/internal/api"
	"github.com/maximalfocus/planless/internal/fixtures"
	"github.com/maximalfocus/planless/internal/platform"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(env("PLANLESS_CORP_ADDR", fixtures.ControlPlaneCorpAddr+":8080")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(log); err != nil {
		log.Error("controlplane.exit", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	corpAddr := env("PLANLESS_CORP_ADDR", fixtures.ControlPlaneCorpAddr+":8080")
	edgeAddr := env("PLANLESS_EDGE_ADDR", "")
	seed := env("PLANLESS_SEED", "secure-baseline")
	scenario := env("PLANLESS_SCENARIO", "secure-baseline")

	store := platform.New(fixtures.Segments())
	switch seed {
	case "secure-baseline":
		fixtures.Seed(store, fixtures.SecureBaseline())
	case "bootstrap":
		fixtures.Seed(store, fixtures.Bootstrap())
	default:
		return fmt.Errorf("unknown seed %q: the control plane accepts only enumerated seeds", seed)
	}
	digest, err := store.Digest()
	if err != nil {
		return err
	}
	log.Info("controlplane.seeded", "seed", seed, "scenario", scenario, "state_digest", digest)

	srv := api.New(store, log, scenario)
	servers := []*http.Server{{
		Addr:              corpAddr,
		Handler:           srv.CorpHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}}
	if edgeAddr != "" {
		servers = append(servers, &http.Server{
			Addr:              edgeAddr,
			Handler:           srv.EdgeHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		})
	}

	errs := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			log.Info("controlplane.listening", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("listen %s: %w", s.Addr, err)
			}
		}(s)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errs:
		return err
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
	return nil
}

// healthcheck answers the container health probe from inside the container.
func healthcheck(addr string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
