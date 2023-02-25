package server

import (
	"context"
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

type PropertyValuesEqualsRequest struct {
	Name     string `json:"name"`
	Previous string `json:"previous"`
	Current  string `json:"current"`
}

type PropertiesValuesEqualsResponse struct {
	Equals bool `json:"equals"`
}

func GetMux(p provider.Provider) *http.ServeMux {
	m := http.NewServeMux()

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Content-Type")
		w.Header().Set("Content-Type", "application/external.dns.plugin+json;version=1")
		w.WriteHeader(http.StatusOK)
	})

	m.HandleFunc("/records", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			records, err := p.Records(context.Background())
			if err != nil {
				log.WithError(err).Error("Failed to fetch records")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(records); err != nil {
				log.WithError(err).Error("Failed to encode records")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			var changes plan.Changes
			if err := json.NewDecoder(r.Body).Decode(&changes); err != nil {
				log.WithError(err).Error("Failed to decode changes")
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := p.ApplyChanges(context.Background(), &changes); err != nil {
				log.WithError(err).Error("Failed to apply changes")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	m.HandleFunc("/adjustendpoints", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var pve []*endpoint.Endpoint
		if err := json.NewDecoder(r.Body).Decode(&pve); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		pve = p.AdjustEndpoints(pve)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(pve); err != nil {
			log.WithError(err).Error("Failed to encode records")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	m.HandleFunc("/propertyvaluesequals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		pve := PropertyValuesEqualsRequest{}
		if err := json.NewDecoder(r.Body).Decode(&pve); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		b := p.PropertyValuesEqual(pve.Name, pve.Previous, pve.Current)
		resp := PropertiesValuesEqualsResponse{
			Equals: b,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.WithError(err).Error("Failed to encode records")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	return m
}
