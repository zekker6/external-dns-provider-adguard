package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/zekker6/external-dns-adguard-provider/adguardhome"
	"github.com/zekker6/external-dns-adguard-provider/server"
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

	m := server.GetMux(p)
	if err := http.ListenAndServe(":8888", m); err != nil {
		log.Fatalf("listen failed error: %v", err)
	}
}
