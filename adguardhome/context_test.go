package adguardhome

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderConstructionDoesNotMakeHTTPRequests(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer s.Close()
	t.Setenv(envURL, s.URL)
	t.Setenv(envUser, "test-user")
	t.Setenv(envPassword, "test-password")
	t.Setenv(envUseDNSRewrite, "true")
	p, err := NewAdguardHomeProvider(context.Background(), false)
	if err != nil {
		t.Fatalf("construction must not depend on AdGuard availability: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("constructor made %d HTTP requests", requests.Load())
	}
	if err = p.Initialize(context.Background()); err == nil {
		t.Fatal("explicit initialization must report the HTTP failure")
	}
	if requests.Load() != 1 {
		t.Fatalf("initialization made %d HTTP requests, want 1", requests.Load())
	}
}

func TestInitializationCancellation(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &AdguardHomeProvider{client: newAdguardHomeClient(context.Background(), s.URL+"/", "test", "test", false), ruleFormat: rewriteRuleFormat()}
	result := make(chan error, 1)
	go func() { result <- p.Initialize(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("initialization request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("initialization error=%v, want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initialization ignored cancellation")
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("outgoing HTTP request ignored cancellation")
	}
}

type contextTestTransport func(*http.Request) (*http.Response, error)

func (f contextTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestClientPropagatesRequestContext(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			type contextKey struct{}
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), contextKey{}, "request-value"), 5*time.Second)
			defer cancel()
			wantDeadline, _ := ctx.Deadline()
			requests := 0
			c := newAdguardHomeClient(context.Background(), "http://adguard.test/control/", "test", "test", false)
			c.hc.Transport = contextTestTransport(func(r *http.Request) (*http.Response, error) {
				requests++
				deadline, ok := r.Context().Deadline()
				if r.Method != method || r.Context().Value(contextKey{}) != "request-value" || !ok || deadline != wantDeadline {
					t.Errorf("HTTP request did not inherit method, deadline and values")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"user_rules":[]}`))}, nil
			})
			var err error
			if method == http.MethodGet {
				_, err = c.GetFilteringRules(ctx)
			} else {
				err = c.SaveFilteringRules(ctx, []string{"# test rule"})
			}
			if err != nil || requests != 1 {
				t.Fatalf("HTTP request error=%v, count=%d", err, requests)
			}
		})
	}
}

func TestInitializeCancelledBeforeRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &AdguardHomeProvider{}
	if err := p.Initialize(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("initialization error=%v, want context cancellation", err)
	}
}
