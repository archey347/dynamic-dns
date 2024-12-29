package internal

import (
	"context"
	"errors"
	"log/slog"
	"time"

	nethttp "net/http"
	"net/netip"

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
	zone := chi.URLParam(r, "zone")
	host := chi.URLParam(r, "host")
	log := ci.log.With("zone", zone).With("host", host).With("remote_addr", r.RemoteAddr)
	log.Info("Recieved request")

	remoteAddrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.WriteErrorResponse(w, 400, "Remote address isn't valid")
		slog.Info("Failed to parse remote address")
		return
	}

	remoteAddr := remoteAddrPort.Addr()

	recordType := "A"
	if remoteAddr.Is6() {
		recordType = "AAAA"
	}

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
		http.WriteErrorResponse(w, 401, "Unauthorized")
		log.Info("Incorrect username")
		return
	}

	// Check password
	if password != key.Secret {
		http.WriteErrorResponse(w, 401, "Unauthorized")
		log.Info("Incorrect password")
		return
	}

	if !isAuthorised(key, zone, host, recordType) {
		http.WriteErrorResponse(w, nethttp.StatusUnauthorized, "Unauthorized")
		log.Info("Key not authorized for zone/host")
		return
	}

	http.WriteDataResponse(w, map[string]string{
		"zone": zone,
		"host": host,
	})
}

func isAuthorised(key *Key, zone string, host string, recordType string) bool {
	// Check this user is allowed to update this zone
	for _, allowed := range key.Allowed {
		if allowed.Zone != zone {
			continue
		}

		// Check host
		for _, hostPattern := range allowed.HostPatterns {
			if hostPattern != host {
				continue
			}

			// Now check record types
			for _, allowedRecordType := range allowed.RecordTypes {
				if allowedRecordType != recordType {
					continue
				}

				return true
			}
		}
	}

	return false
}
