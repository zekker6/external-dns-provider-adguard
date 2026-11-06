package adguardhome

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// Client is an interface for the AdguardHome API.
// See OpenAPI spec for details: https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml
type Client interface {
	GetFilteringRules(ctx context.Context) ([]string, error)
	SaveFilteringRules(ctx context.Context, rules []string) error
}

type client struct {
	hc           *http.Client
	lifecycleCtx context.Context

	endpoint string
	user     string
	pass     string
	dryRun   bool
}

type filteringStatus struct {
	UserRules []string `json:"user_rules"`
}

type setRules struct {
	Rules []string `json:"rules"`
}

// requestContext preserves operation deadlines and values while linking shutdown
// cancellation. Release it only after the response body has been closed.
func (c *client) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	requestCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifecycleCtx, cancel)
	if c.lifecycleCtx.Err() != nil {
		cancel()
	}
	return requestCtx, func() {
		stop()
		cancel()
	}
}

func (c *client) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	log.Debugf("making %s request to %s", method, path)

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}

	log.Debugf("response status code %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	return resp, nil
}

func (c *client) GetFilteringRules(ctx context.Context) ([]string, error) {
	if c.dryRun {
		return []string{}, nil
	}

	ctx, release := c.requestContext(ctx)
	defer release()
	r, err := c.doRequest(ctx, http.MethodGet, "filtering/status", nil)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var resp filteringStatus
	err = json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		return nil, err
	}

	return resp.UserRules, nil
}

func (c *client) SaveFilteringRules(ctx context.Context, rules []string) error {
	if c.dryRun {
		return nil
	}

	ctx, release := c.requestContext(ctx)
	defer release()
	body := setRules{Rules: rules}

	b := bytes.NewBuffer(nil)
	err := json.NewEncoder(b).Encode(body)
	if err != nil {
		return err
	}

	r, err := c.doRequest(ctx, http.MethodPost, "filtering/set_rules", b)
	if err != nil {
		return err
	}
	_ = r.Body.Close()
	return nil
}

func newAdguardHomeClient(ctx context.Context, endpoint, user, pass string, dryRun bool) *client {
	hc := http.Client{}
	return &client{
		hc:           &hc,
		lifecycleCtx: ctx,
		endpoint:     endpoint,
		user:         user,
		pass:         pass,

		dryRun: dryRun,
	}
}
