package adguardhome

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestTXTRewriteRestrictsQueryType(t *testing.T) {
	rule, err := dnsRewriteRule(&endpoint.Endpoint{
		DNSName: "example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{"verification-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule != "|example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;verification-token" {
		t.Fatalf("TXT rewrite must not intercept other query types: %s", rule)
	}
}

func TestTXTRewriteEscapesCosmeticMarkers(t *testing.T) {
	for _, target := range []string{"a##b", "a#@#b", "a#?#b", "a#%#b", "a #$#b"} {
		t.Run(target, func(t *testing.T) {
			value, err := txtRewriteValue(target)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(value, "#") || !strings.Contains(value, `\035`) {
				t.Fatalf("cosmetic markers must be DNS-escaped: %s", value)
			}
		})
	}
}

func TestRewriteRejectsWildcardWithoutWriting(t *testing.T) {
	for _, recordType := range []string{endpoint.RecordTypeA, endpoint.RecordTypeTXT} {
		t.Run(recordType, func(t *testing.T) {
			wildcard := &endpoint.Endpoint{DNSName: "*.apps.example.com", RecordType: recordType, Targets: endpoint.Targets{"192.0.2.10"}}
			exact := &endpoint.Endpoint{DNSName: "api.apps.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.11"}}
			original := []string{"# preserve this rule"}
			c := &mockAdguardClient{rules: append([]string(nil), original...)}
			p := &AdguardHomeProvider{client: c, ruleFormat: rewriteRuleFormat()}
			if err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{exact, wildcard}}); err == nil {
				t.Fatal("expected wildcard rejection")
			}
			if !reflect.DeepEqual(c.rules, original) {
				t.Fatalf("wildcard failure overwrote rules: %v", c.rules)
			}

			legacy := []string{endpointToString(wildcard, managedBy)}
			c.rules = append([]string(nil), legacy...)
			if err := p.migrateRules(context.Background()); err == nil {
				t.Fatal("expected migration of a wildcard to fail")
			}
			if !reflect.DeepEqual(c.rules, legacy) {
				t.Fatalf("migration failure overwrote rules: %v", c.rules)
			}
		})
	}
}

func TestRuleBoundaryWhitespacePreservesOwnership(t *testing.T) {
	for _, tt := range []struct {
		name   string
		format ruleFormat
	}{
		{name: "legacy", format: legacyRuleFormat()},
		{name: "rewrite", format: rewriteRuleFormat()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			endpoints := []*endpoint.Endpoint{
				{DNSName: "app.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.10"}},
				{DNSName: "txt.example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{" token "}},
			}
			managed, err := tt.format.formatRules(endpoints, managedBy)
			if err != nil {
				t.Fatal(err)
			}
			unmanaged := []string{"  # keep surrounding whitespace  ", "192.0.2.99 other.example.com #$managed by external-dns;ref:other \t"}
			rules := append([]string(nil), unmanaged...)
			for _, rule := range managed {
				rules = append(rules, " \t"+rule+" \t\r")
			}
			c := &mockAdguardClient{rules: rules}
			p := &AdguardHomeProvider{client: c, ruleFormat: tt.format}
			ctx := context.Background()
			records, err := p.Records(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(records, endpoints) {
				t.Fatalf("boundary whitespace changed ownership or TXT content: got %+v, want %+v", records, endpoints)
			}
			if err = p.migrateRules(ctx); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.rules, rules) {
				t.Fatalf("boundary whitespace caused unnecessary migration: %v", c.rules)
			}
			if err = p.ApplyChanges(ctx, &plan.Changes{Delete: endpoints}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.rules, unmanaged) {
				t.Fatalf("deletion left managed rules or changed unmanaged text: got %v, want %v", c.rules, unmanaged)
			}
		})
	}
}
