package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/provider/webhook/api"

	"github.com/zekker6/external-dns-adguard-provider/adguardhome"
)

// Shifting left by 20 multiplies by 2^20, converting 32 MiB to bytes.
const defaultMaxRequestBodySize = 32 << 20

var (
	dryRun      = flag.Bool("dry-run", false, "Do not apply changes, just print them")
	logLevel    = flag.String("log-level", "info", "Log level (debug, info, error)")
	maxBodySize = flag.Int64("max-body-size", defaultMaxRequestBodySize, "Maximum webhook request body size in bytes (0 or less disables the limit)")
)

func main() {
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{})

	switch *logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		fmt.Printf("Invalid log level: %s", *logLevel)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p, err := adguardhome.NewAdguardHomeProvider(ctx, *dryRun)
	if err != nil {
		log.WithError(err).Error("Failed to create AdguardHomeProvider")
		os.Exit(1)
	}
	if err := p.Initialize(ctx); err != nil {
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return
		}
		log.WithError(err).Error("Failed to initialize AdguardHomeProvider")
		os.Exit(1)
	}
	if ctx.Err() != nil {
		return
	}
	started := make(chan struct{}, 1)
	go api.StartHTTPApi(api.ServerOptions{
		Provider:     p,
		StartedChan:  started,
		ProviderPort: ":8888",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		MaxBodySize:  *maxBodySize,
	})
	select {
	case <-started:
		log.Info("AdguardHomeProvider started on :8888")
	case <-ctx.Done():
		return
	}
	<-ctx.Done()
}
