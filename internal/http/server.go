package http

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	config *Config
	log    *slog.Logger
	server *http.Server
}

func NewServer(config *Config, registerRoutes func(r *chi.Mux), log *slog.Logger) *Server {
	s := &Server{
		config: config,
		log:    log,
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)

	rec := &Recoverer{log: log}
	r.Use(rec.Recover)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		WriteErrorResponse(w, http.StatusNotFound, "not found")
	})

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(time.Duration(30) * time.Second))

	registerRoutes(r)

	s.server = &http.Server{
		Addr:    config.Bind,
		Handler: r,
	}

	return s
}

func (s *Server) Start() error {
	s.log.Info("Listening on 'http://" + s.config.Bind + "'")
	err := s.server.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
