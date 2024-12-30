package main

import (
	"log/slog"
	"os"

	"github.com/archey347/dynamic-dns/internal"
)

func main() {
	l := slog.With("service", "dynamic-dns-server")
	l.Info("Starting")

	// Load Config
	c, err := internal.LoadConfig(os.Getenv("DYNAMIC_DNS_CONFIG"))
	if err != nil {
		l.Error("Failed to load config", "error", err.Error())
		return
	}

	err = internal.Start(c, l)
	if err != nil {
		l.Error("Failed to start", "error", err.Error())
	}

	l.Info("Stopped")
}
