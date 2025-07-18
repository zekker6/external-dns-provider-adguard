package adguardhome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/provider"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

var (
	errNotManaged = fmt.Errorf("rule is managed by external-dns")
)

const (
	managedBy = "$managed by external-dns"

	envURL       = "ADGUARD_HOME_URL"
	envPassword  = "ADGUARD_HOME_PASS"
	envUser      = "ADGUARD_HOME_USER"
	envManagedBy = "ADGUARD_HOME_MANAGED_BY_REF"
)

// Client is an interface for the AdguardHome API.
// See OpenAPI spec for details: https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml
type Client interface {
	GetFilteringRules(ctx context.Context) ([]string, error)
	SaveFilteringRules(ctx context.Context, rules []string) error
}

type AdguardHomeProvider struct {
	provider.BaseProvider

	client Client

	domainFilter *endpoint.DomainFilter

	managedBySuffix string
}

// NewAdguardHomeProvider initializes a new AdguardHome based provider
func NewAdguardHomeProvider(dryRun bool) (*AdguardHomeProvider, error) {
	adguardHomeURL, adguardHomeUrlOk := os.LookupEnv(envURL)
	if !adguardHomeUrlOk {
		return nil, fmt.Errorf("no url was found in environment variable ADGUARD_HOME_URL")
	}

	// Adjust the URL to match the API requirements
	if !strings.HasSuffix(adguardHomeURL, "/") {
		adguardHomeURL = adguardHomeURL + "/"
	}

	if !strings.HasSuffix(adguardHomeURL, "control/") {
		adguardHomeURL = adguardHomeURL + "control/"
	}

	adguardHomeUser, adguardHomeUserOk := os.LookupEnv(envUser)
	if !adguardHomeUserOk {
		return nil, fmt.Errorf("no user was found in environment variable ADGUARD_HOME_USER")
	}

	adguardHomePass, adguardHomePassOk := os.LookupEnv(envPassword)
	if !adguardHomePassOk {
		return nil, fmt.Errorf("no password was found in environment variable ADGUARD_HOME_PASS")
	}

	c, err := newAdguardHomeClient(adguardHomeURL, adguardHomeUser, adguardHomePass, dryRun)
	if err != nil {
		return nil, fmt.Errorf("failed to create the adguard home api hс: %w", err)
	}
	managedBySuffix, _ := os.LookupEnv(envManagedBy)

	p := &AdguardHomeProvider{
		client:          c,
		domainFilter:    &endpoint.DomainFilter{},
		managedBySuffix: managedBySuffix,
	}

	log.Debugf("AdguardHome provider started with url %s", adguardHomeURL)

	return p, nil
}

func (p *AdguardHomeProvider) getManagedBy() string {
	if p.managedBySuffix == "" {
		return managedBy
	}

	return fmt.Sprintf("%s;ref:%s", managedBy, p.managedBySuffix)
}

// ApplyChanges implements Provider, syncing desired state with the AdguardHome server Local DNS.
func (p *AdguardHomeProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	log.Debugf("ApplyChanges: %+v", changes)

	originalRules, err := p.client.GetFilteringRules(ctx)
	if err != nil {
		return err
	}

	log.Debugf("loaded existing rules: %+v", originalRules)

	resultingRules := make([]string, 0)
	endpoints := make([]*endpoint.Endpoint, 0)
	endpointsAExists := make(map[string]*endpoint.Endpoint)
	suffix := p.getManagedBy()
	for _, rule := range originalRules {
		e, err := parseRule(rule, suffix)
		if err != nil {
			// Keep rules not managed by external-dns as-is
			if errors.Is(err, errNotManaged) {
				resultingRules = append(resultingRules, rule)
				continue
			}
			return fmt.Errorf("failed to parse rule %s: %w", rule, err)
		}

		if endpointsAExists[e.DNSName] != nil {
			endpointsAExists[e.DNSName].Targets = append(endpointsAExists[e.DNSName].Targets, e.Targets...)
		} else {
			endpoints = append(endpoints, e)
			endpointsAExists[e.DNSName] = e
		}
	}

	for _, deleteEndpoint := range append(changes.UpdateOld, changes.Delete...) {
		for _, target := range deleteEndpoint.Targets {
			for endpointIndex, endpointValue := range endpoints {
				if endpointValue.DNSName == deleteEndpoint.DNSName && endpointValue.RecordType == deleteEndpoint.RecordType && endpointValue.Targets[0] == target {
					endpoints = append(endpoints[:endpointIndex], endpoints[endpointIndex+1:]...)
					log.Debugf("delete custom rule %s", deleteEndpoint)
					break
				}
			}
		}
	}

	for _, createEndpoint := range append(changes.Create, changes.UpdateNew...) {
		if !endpointSupported(createEndpoint) {
			continue
		}

		for _, target := range createEndpoint.Targets {
			endpoints = append(endpoints, &endpoint.Endpoint{
				DNSName:    createEndpoint.DNSName,
				Targets:    endpoint.Targets{target},
				RecordType: createEndpoint.RecordType,
			})
		}
		log.Debugf("add custom rule %s", createEndpoint)
	}

	for _, e := range endpoints {
		s := endpointToString(e, suffix)
		resultingRules = append(resultingRules, s)
	}

	return p.client.SaveFilteringRules(ctx, resultingRules)
}

// Records implements Provider, populating a slice of endpoints from
// AdguardHome local DNS.
func (p *AdguardHomeProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	resp, err := p.client.GetFilteringRules(ctx)
	if err != nil {
		log.Errorf("Error %s", err)
		return nil, err
	}

	log.WithFields(log.Fields{
		"func":  "records",
		"rules": resp,
	}).Debugf("retrieved AdguardHome rules")

	var ret []*endpoint.Endpoint
	endpointsAExists := make(map[string]*endpoint.Endpoint)
	suffix := p.getManagedBy()
	for _, rule := range resp {
		e, err := parseRule(rule, suffix)
		if err != nil {
			if errors.Is(err, errNotManaged) {
				continue
			}
			return nil, err
		}

		if !p.domainFilter.Match(e.DNSName) {
			continue
		}
		if endpointsAExists[e.DNSName] != nil {
			endpointsAExists[e.DNSName].Targets = append(endpointsAExists[e.DNSName].Targets, e.Targets...)
		} else {
			ret = append(ret, e)
			endpointsAExists[e.DNSName] = e
		}
	}

	return ret, nil
}

// endpointSupported returns true if the endpoint is supported by the provider
// it is only possible to store A and TXT records in AdguardHome
func endpointSupported(e *endpoint.Endpoint) bool {
	return e.RecordType == endpoint.RecordTypeA || e.RecordType == endpoint.RecordTypeTXT
}

func parseRule(rule, suffix string) (*endpoint.Endpoint, error) {
	if !strings.Contains(rule, suffix) {
		return nil, errNotManaged
	}

	if strings.HasPrefix(rule, "#") {
		r := &endpoint.Endpoint{
			RecordType: endpoint.RecordTypeTXT,
		}
		parts := strings.SplitN(rule, " ", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid rule: %s", rule)
		}
		r.DNSName = parts[2]
		r.Targets = endpoint.Targets{strings.ReplaceAll(parts[1], suffix, "")}

		return r, nil
	}

	parts := strings.SplitN(rule, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid rule: %s", rule)
	}

	r := &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeA,
		DNSName:    parts[1],
		Targets:    endpoint.Targets{parts[0]},
	}

	return r, nil
}

func endpointToString(e *endpoint.Endpoint, suffix string) string {
	if e.RecordType == endpoint.RecordTypeTXT {
		return fmt.Sprintf("# %s %s %s", e.Targets[0], e.DNSName, suffix)
	}

	return fmt.Sprintf("%s %s #%s", e.Targets[0], e.DNSName, suffix)
}

type client struct {
	hc *http.Client

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

func (c *client) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
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

func (c *client) status(ctx context.Context) error {
	if c.dryRun {
		return nil
	}

	r, err := c.doRequest(ctx, http.MethodGet, "status", nil)
	if err != nil {
		return err
	}
	_ = r.Body.Close()
	return nil
}

func (c *client) GetFilteringRules(ctx context.Context) ([]string, error) {
	if c.dryRun {
		return []string{}, nil
	}

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

func newAdguardHomeClient(endpoint, user, pass string, dryRun bool) (*client, error) {
	hc := http.Client{}
	c := &client{
		hc:       &hc,
		endpoint: endpoint,
		user:     user,
		pass:     pass,

		dryRun: dryRun,
	}

	err := c.status(context.Background())
	if err != nil {
		return nil, err
	}

	return c, nil
}
