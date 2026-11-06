package adguardhome

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProviderHTTPRequestsCancelWithEitherContext(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, cancelGlobal := range []bool{false, true} {
			name := method + "/operation"
			if cancelGlobal {
				name = method + "/global"
			}
			t.Run(name, func(t *testing.T) {
				started := make(chan struct{})
				cancelled := make(chan struct{})
				s := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					if r.Method != method {
						t.Errorf("HTTP method=%s, want %s", r.Method, method)
					}
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Errorf("read request body: %v", err)
						return
					}
					close(started)
					<-r.Context().Done()
					close(cancelled)
				}))
				defer s.Close()
				root, cancelRoot := context.WithCancel(context.Background())
				defer cancelRoot()
				op, cancelOp := context.WithCancel(context.Background())
				defer cancelOp()
				t.Setenv(envURL, s.URL)
				t.Setenv(envUser, "test")
				t.Setenv(envPassword, "test")
				t.Setenv(envUseDNSRewrite, "false")
				p, err := NewAdguardHomeProvider(root, false)
				if err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() {
					if method == http.MethodGet {
						_, err := p.Records(op)
						result <- err
					} else {
						result <- p.client.SaveFilteringRules(op, []string{"# test rule"})
					}
				}()
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("HTTP request did not start")
				}
				if cancelGlobal {
					cancelRoot()
				} else {
					cancelOp()
				}
				select {
				case err := <-result:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("HTTP request error=%v, want cancellation", err)
					}
				case <-time.After(time.Second):
					t.Fatal("HTTP request ignored cancellation")
				}
				select {
				case <-cancelled:
				case <-time.After(5 * time.Second):
					t.Fatal("server did not observe cancellation")
				}
			})
		}
	}
}

type lifecycleTestBody struct {
	ctx context.Context
	*strings.Reader
	closed bool
}

func (b *lifecycleTestBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	return b.Reader.Read(p)
}

func (b *lifecycleTestBody) Close() error {
	b.closed = true
	return nil
}

func TestClientKeepsContextAliveUntilBodyConsumed(t *testing.T) {
	c := newAdguardHomeClient(context.Background(), "http://adguard.test/control/", "test", "test", false)
	var body *lifecycleTestBody
	c.hc.Transport = contextTestTransport(func(r *http.Request) (*http.Response, error) {
		body = &lifecycleTestBody{ctx: r.Context(), Reader: strings.NewReader(`{"user_rules":["# present"]}`)}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	rules, err := c.GetFilteringRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rules, []string{"# present"}) || !body.closed {
		t.Fatalf("response body was not fully consumed and closed: rules=%v closed=%t", rules, body.closed)
	}
	if !errors.Is(body.ctx.Err(), context.Canceled) {
		t.Fatal("request context was not released after the body was consumed")
	}
}

func TestClientRejectsRequestsAfterGlobalCancellation(t *testing.T) {
	root, cancel := context.WithCancel(context.Background())
	cancel()
	c := newAdguardHomeClient(root, "http://adguard.test/control/", "test", "test", false)
	requests := 0
	c.hc.Transport = contextTestTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Body: &lifecycleTestBody{ctx: r.Context(), Reader: strings.NewReader(`{"user_rules":[]}`)}}, nil
	})
	if _, err := c.GetFilteringRules(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("GET error=%v, want cancellation", err)
	}
	if err := c.SaveFilteringRules(context.Background(), []string{"# test rule"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("POST error=%v, want cancellation", err)
	}
	if requests != 0 {
		t.Fatalf("sent %d HTTP requests after shutdown", requests)
	}
}
