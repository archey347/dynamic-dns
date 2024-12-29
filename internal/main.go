package internal

import (
	"context"
	"errors"
	"log/slog"
	"time"

	nethttp "net/http"

	"github.com/archey347/dynamic-dns/dynamic-dns/internal/http"
	"github.com/coreos/go-systemd/daemon"
	"github.com/go-chi/chi"
	"golang.org/x/sync/errgroup"
)

type Container struct {
	config *Config
	log    *slog.Logger
}

func Start(config *Config, log *slog.Logger) error {
	ci := &Container{
		config: config,
		log:    log,
	}

	s := http.NewServer(&config.Http, GetRouteRegistrar(ci), log)

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		l := log.With("component", "watchdog")
		l.Info("Starting")
		watchdog(ctx)

		return nil
	})

	g.Go(func() error {
		l := log.With("component", "http-server")
		l.Info("Starting")

		err := s.Start()
		if err != nil {
			l.Error("Failed to start", "error", err.Error())
		}

		return errors.New("Failed to start http server component")
	})

	return g.Wait()
}

func watchdog(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			daemon.SdNotify(false, daemon.SdNotifyWatchdog)
			time.Sleep(1 * time.Second)
		}
	}
}

func GetRouteRegistrar(ci *Container) func(r *chi.Mux) {
	return func(r *chi.Mux) {
		r.Post("/zones/{zone}/dynamic/{host}", ci.Handle)
	}
}

func (ci *Container) Handle(w nethttp.ResponseWriter, r *nethttp.Request) {
	remoteAddr := r.RemoteAddr
	zone := chi.URLParam(r, "zone")
	host := chi.URLParam(r, "host")
	log := ci.log.With("zone", zone).With("host", host).With("remote_addr", remoteAddr)
	log.Info("Recieved request")

	// Ask for credentials
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.WriteErrorResponse(w, nethttp.StatusUnauthorized, "Unauthorized")

		log.Info("Client failed to authenticate")
		return
	}

	// Check username is valid
	var key *Key
	if key, ok = ci.config.Keys[username]; !ok {
		http.WriteErrorResponse(w, 400, "Invalid credentials")
		log.Info("Incorrect username")
		return
	}

	// Check password
	if password != key.Secret {
		http.WriteErrorResponse(w, 400, "Invalid credentials")
		log.Info("Incorrect password")
		return
	}

	http.WriteDataResponse(w, map[string]string{
		"zone": zone,
		"host": host,
	})
}
