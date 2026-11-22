package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/archey347/dynamic-dns/internal"
)

func main() {
	l := slog.With("service", "dynamic-dns-server")
	l.Info("Starting")

	// Without a handler, Go exits with status 2 on SIGTERM, so every stop looked like a failure.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	c, err := internal.LoadConfig(os.Getenv("DYNAMIC_DNS_CONFIG"))
	if err != nil {
		l.Error("Failed to load config", "error", err.Error())
		os.Exit(1)
	}

	err = internal.Start(ctx, c, l)
	if err != nil {
		l.Error("Failed to start", "error", err.Error())
		os.Exit(1)
	}

	l.Info("Stopped")
}
