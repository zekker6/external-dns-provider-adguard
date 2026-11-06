package adguardhome

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/provider"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

var (
	errNotManaged       = fmt.Errorf("rule is managed by external-dns")
	errArtificialRecord = fmt.Errorf("artificial domain rule")
)

const (
	managedBy = "$managed by external-dns"

	envURL           = "ADGUARD_HOME_URL"
	envPassword      = "ADGUARD_HOME_PASS"
	envUser          = "ADGUARD_HOME_USER"
	envManagedBy     = "ADGUARD_HOME_MANAGED_BY_REF"
	envUseDNSRewrite = "ADGUARD_HOME_USE_DNSREWRITE"
)

type AdguardHomeProvider struct {
	provider.BaseProvider

	client Client

	domainFilter *endpoint.DomainFilter

	managedBySuffix string
	ruleFormat      ruleFormat
}

// NewAdguardHomeProvider configures a provider without making HTTP requests.
// Cancelling ctx cancels outgoing AdGuard HTTP requests throughout its lifetime.
func NewAdguardHomeProvider(ctx context.Context, dryRun bool) (*AdguardHomeProvider, error) {
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

	var useDNSRewrite bool
	if value := os.Getenv(envUseDNSRewrite); value != "" {
		var err error
		useDNSRewrite, err = strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", envUseDNSRewrite, err)
		}
	}

	c := newAdguardHomeClient(ctx, adguardHomeURL, adguardHomeUser, adguardHomePass, dryRun)
	managedBySuffix, _ := os.LookupEnv(envManagedBy)

	format := legacyRuleFormat()
	if useDNSRewrite {
		format = rewriteRuleFormat()
	}
	p := &AdguardHomeProvider{
		client:          c,
		domainFilter:    &endpoint.DomainFilter{},
		managedBySuffix: managedBySuffix,
		ruleFormat:      format,
	}

	log.Debugf("AdguardHome provider configured with url %s", adguardHomeURL)

	return p, nil
}

// Initialize migrates managed filtering rules before the webhook starts serving.
func (p *AdguardHomeProvider) Initialize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.migrateRules(ctx); err != nil {
		return fmt.Errorf("failed to migrate filtering rules: %w", err)
	}
	return nil
}

func (p *AdguardHomeProvider) getManagedBy() string {
	if p.managedBySuffix == "" {
		return managedBy
	}

	return fmt.Sprintf("%s;ref:%s", managedBy, p.managedBySuffix)
}

// migrateRules runs at startup because ExternalDNS does not call ApplyChanges
// when the desired DNS records have not changed.
func (p *AdguardHomeProvider) migrateRules(ctx context.Context) error {
	rules, err := p.client.GetFilteringRules(ctx)
	if err != nil {
		return err
	}

	for _, original := range rules {
		rule := strings.TrimSpace(original)
		e, err := parseRule(rule, p.getManagedBy())
		if errors.Is(err, errNotManaged) || errors.Is(err, errArtificialRecord) {
			continue
		}
		if err != nil {
			return err
		}
		if endpointSupported(e) && p.ruleFormat.needsMigration(rule) {
			log.Info("Migrating managed filtering rules")
			return p.applyChanges(ctx, rules, &plan.Changes{})
		}
	}

	return nil
}

// ApplyChanges implements Provider, syncing desired state with the AdguardHome server Local DNS.
func (p *AdguardHomeProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	log.Debugf("ApplyChanges: %+v", changes)

	originalRules, err := p.client.GetFilteringRules(ctx)
	if err != nil {
		return err
	}

	return p.applyChanges(ctx, originalRules, changes)
}

func (p *AdguardHomeProvider) applyChanges(ctx context.Context, originalRules []string, changes *plan.Changes) error {
	log.Debugf("loaded existing rules: %+v", originalRules)

	suffix := p.getManagedBy()
	endpoints, resultingRules, err := parseRules(originalRules, suffix)
	if err != nil {
		return err
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
				Labels:     createEndpoint.Labels,
			})
		}
		log.Debugf("add custom rule %s", createEndpoint)
	}

	managedRules, err := p.ruleFormat.formatRules(endpoints, suffix)
	if err != nil {
		return err
	}
	resultingRules = append(resultingRules, managedRules...)

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

	endpoints, _, err := parseRules(resp, p.getManagedBy())
	if err != nil {
		return nil, err
	}

	var ret []*endpoint.Endpoint
	endpointsByKey := make(map[endpoint.EndpointKey]*endpoint.Endpoint)
	for _, e := range endpoints {
		if !p.domainFilter.Match(e.DNSName) {
			continue
		}
		key := e.Key()
		if endpointsByKey[key] != nil {
			endpointsByKey[key].Targets = append(endpointsByKey[key].Targets, e.Targets...)
		} else {
			ret = append(ret, e)
			endpointsByKey[key] = e
		}
	}

	return ret, nil
}

// endpointSupported returns true if the endpoint is supported by the provider
// it is only possible to store A and TXT records in AdguardHome
func endpointSupported(e *endpoint.Endpoint) bool {
	return e.RecordType == endpoint.RecordTypeA || e.RecordType == endpoint.RecordTypeTXT
}
