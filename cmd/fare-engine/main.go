// Command fare-engine is the Halloway fare engine workload.
//
// It is an ordinary, correct application. It is byte-identical in every variant
// of the demonstration: no request handler, authorization check, or response
// differs between the secure and the misconfigured platform. The only thing
// that ever changes is what the platform is configured to let reach it.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// defaultFareCap is the fictional fare cap in minor units.
const defaultFareCap = 250

// raisedFareCap is the single enumerated, documented, non-destructive state
// transition the admin surface offers.
const raisedFareCap = 400

type engine struct {
	mu      sync.Mutex
	fareCap int
	log     *slog.Logger
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	bind := os.Getenv("PLANLESS_BIND")
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(bind); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if bind == "" {
		log.Error("fare-engine.exit", "error", "PLANLESS_BIND is required")
		os.Exit(1)
	}
	e := &engine{fareCap: defaultFareCap, log: log}

	service := &http.Server{
		Addr:              bind + ":8080",
		Handler:           e.serviceHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	admin := &http.Server{
		Addr:              bind + ":8081",
		Handler:           e.adminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errs := make(chan error, 2)
	for _, s := range []*http.Server{service, admin} {
		go func(s *http.Server) {
			log.Info("fare-engine.listening", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("listen %s: %w", s.Addr, err)
			}
		}(s)
	}
	err := <-errs
	log.Error("fare-engine.exit", "error", err.Error())
	os.Exit(1)
}

func (e *engine) serviceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /fares", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		capMinor := e.fareCap
		e.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"operator":       "Halloway Transit Authority",
			"fare_cap_minor": capMinor,
			"routes": []map[string]any{
				{"route": "orbital-loop", "fare_minor": 340},
				{"route": "harbour-line", "fare_minor": 275},
				{"route": "northgate-shuttle", "fare_minor": 190},
			},
		})
	})
	return mux
}

func (e *engine) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /admin/status", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		capMinor := e.fareCap
		e.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"surface":        "admin",
			"fare_cap_minor": capMinor,
			"caller":         r.Header.Get("X-Democloud-Caller-Principal"),
			"segment":        r.Header.Get("X-Democloud-Caller-Segment"),
		})
	})
	// The one enumerated transition. It raises a fictional fare cap and nothing
	// else: there is no free-form administrative action on this surface.
	mux.HandleFunc("POST /admin/fare-cap", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.fareCap = raisedFareCap
		capMinor := e.fareCap
		e.mu.Unlock()
		e.log.Info("fare-engine.fare_cap_raised",
			"fare_cap_minor", capMinor,
			"caller", r.Header.Get("X-Democloud-Caller-Principal"),
			"segment", r.Header.Get("X-Democloud-Caller-Segment"))
		w.Header().Set("X-Democloud-Change", fmt.Sprintf("fare-cap=%d", capMinor))
		writeJSON(w, http.StatusOK, map[string]any{"surface": "admin", "fare_cap_minor": capMinor})
	})
	return mux
}

// healthcheck answers the container health probe from inside the container.
func healthcheck(bind string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	for _, port := range []string{":8080", ":8081"} {
		resp, err := client.Get("http://" + bind + port + "/healthz")
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz on %s returned %d", port, resp.StatusCode)
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
