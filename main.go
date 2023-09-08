package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/provider/webhook"

	"github.com/zekker6/external-dns-adguard-provider/adguardhome"
)

var (
	dryRun   = flag.Bool("dry-run", false, "Do not apply changes, just print them")
	logLevel = flag.String("log-level", "info", "Log level (debug, info, error)")
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

	p, err := adguardhome.NewAdguardHomeProvider(*dryRun)
	if err != nil {
		log.WithError(err).Fatal("Failed to create AdguardHomeProvider")
		os.Exit(1)
	}

	st := make(chan struct{})
	go func() {
		<-st
		log.Info("AdguardHomeProvider started on :8888")
	}()
	webhook.StartHTTPApi(p, st, 10*time.Second, 10*time.Second, ":8888")
}
