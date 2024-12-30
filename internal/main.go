package internal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	nethttp "net/http"
	"net/netip"

	"github.com/archey347/dynamic-dns/internal/http"
	"github.com/coreos/go-systemd/daemon"
	"github.com/go-chi/chi"
	"github.com/miekg/dns"
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

	nameservers := ci.config.Zones[zone].Nameservers
	for _, ns := range nameservers {
		var nsConfig *Nameserver
		if nsConfig, ok = ci.config.Nameservers[ns]; !ok {
			log.Error("Failed to find nameserver", "nameserver", ns)
			continue
		}

		err = update(nsConfig, zone, host, recordType, remoteAddr)
		if err != nil {
			log.Error("Failed to update dns", "ns", ns, "error", err.Error())
		}
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

func update(ns *Nameserver, zone string, host string, recordType string, value netip.Addr) error {
	if zone == "" || zone[len(zone)-1] != '.' {
		zone = zone + "."
	}

	fqdn := host + "." + zone

	rrs := make([]dns.RR, 1)

	if recordType == "A" {
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(3600)}
		rr.A = net.ParseIP(value.String())

		rrs[0] = rr
	} else if recordType == "AAAA" {
		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(3600)}
		rr.AAAA = net.ParseIP(value.String())

		rrs[0] = rr
	}

	m := new(dns.Msg)
	m.SetUpdate(zone)

	m.RemoveRRset(rrs)
	m.Insert(rrs)

	// Setup client
	c := &dns.Client{Timeout: time.Duration(30) * time.Second}

	m.SetTsig(ns.Key.Name, dns.HmacSHA512, 300, time.Now().Unix())
	c.TsigSecret = map[string]string{ns.Key.Name: ns.Key.Secret}

	// Send the query
	reply, _, err := c.Exchange(m, ns.Address+":53")
	if err != nil {
		return fmt.Errorf("DNS update failed: %w", err)
	}
	if reply != nil && reply.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS update failed: server replied: %s", dns.RcodeToString[reply.Rcode])
	}

	return nil
}
