package adguardhome

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestTXTRewriteValues(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target string
		value  string
	}{
		{name: "plain", target: "verification-token", value: "verification-token"},
		{name: "spaces", target: "v=spf1 include:example.com -all", value: `v=spf1\032include:example.com\032-all`},
		{name: "quoted ownership", target: `"heritage=external-dns,external-dns/owner=test"`, value: `heritage=external-dns\044external-dns/owner=test`},
		{name: "reserved characters", target: `a,b$important "quoted" C:\path`, value: `a\044b\036important\032\034quoted\034\032C:\092path`},
		{name: "quoted escapes", target: `"a\"b\\c\044\036"`, value: `a\034b\092c\044\036`},
		{name: "trailing space", target: "token ", value: `token\032`},
		{name: "label-like content", target: "token;labels=not-json", value: "token;labels=not-json"},
		{name: "management marker in content", target: "$managed by external-dns", value: `\036managed\032by\032external-dns`},
		{name: "metadata-like content", target: "$managed by external-dns;labels=not-json", value: `\036managed\032by\032external-dns;labels=not-json`},
		{name: "unicode", target: "é", value: `\195\169`},
		{name: "decimal byte", target: `"\255"`, value: `\255`},
		{name: "empty", target: "", value: ""},
		{name: "quoted empty", target: `""`, value: ""},
		{name: "maximum length", target: strings.Repeat("x", 255), value: strings.Repeat("x", 255)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &mockAdguardClient{}
			p := &AdguardHomeProvider{client: c, ruleFormat: rewriteRuleFormat()}
			e := &endpoint.Endpoint{DNSName: "txt.example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{tt.target}, Labels: endpoint.Labels{"owner": "test"}}
			if err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{e}}); err != nil {
				t.Fatal(err)
			}
			if len(c.rules) != 2 || c.rules[1] != "|txt.example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;"+tt.value {
				t.Fatalf("unexpected rules: %v", c.rules)
			}
			records, err := p.Records(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(records, []*endpoint.Endpoint{e}) {
				t.Fatalf("TXT endpoint changed: got %+v, want %+v", records, e)
			}
			before := append([]string(nil), c.rules...)
			if err = p.ApplyChanges(context.Background(), &plan.Changes{}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.rules, before) {
				t.Fatalf("reconciliation changed TXT rules: %v", c.rules)
			}
			p.ruleFormat = legacyRuleFormat()
			if err = p.migrateRules(context.Background()); err != nil {
				t.Fatal(err)
			}
			records, err = p.Records(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(records, []*endpoint.Endpoint{e}) {
				t.Fatalf("rollback changed TXT endpoint: got %+v, want %+v", records, e)
			}
		})
	}
}

func TestTXTRewriteValidation(t *testing.T) {
	for _, target := range []string{
		strings.Repeat("x", 256),
		strings.Repeat("é", 128),
		`"unterminated`,
		`"a" "b"`,
		`"bad\999"`,
		`"bad\256"`,
		`"bad\"`,
		"injected\n||example.com^",
	} {
		t.Run(target, func(t *testing.T) {
			c := &mockAdguardClient{rules: []string{"# existing rule"}}
			p := &AdguardHomeProvider{client: c, ruleFormat: rewriteRuleFormat()}
			err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{
				{DNSName: "txt.example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{target}},
			}})
			if err == nil {
				t.Fatal("expected invalid TXT value to fail")
			}
			if !reflect.DeepEqual(c.rules, []string{"# existing rule"}) {
				t.Fatalf("invalid value overwrote rules: %v", c.rules)
			}
		})
	}
}

func TestTXTRewriteMigrationAndRollback(t *testing.T) {
	legacy := []string{
		"# keep this comment",
		`# "heritage=external-dns,external-dns/owner=test" app.example.com $managed by external-dns;ref:test;labels={"owner":"test"}`,
		"# v=spf1 include:example.com -all app.example.com $managed by external-dns;ref:test",
	}
	a := setupRewriteTest(t, legacy, "true")
	p, err := newInitializedTestProvider(false)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, writes := a.snapshot()
	if writes != 1 || len(rewritten) != 5 || rewritten[2] != `|app.example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;heritage=external-dns\044external-dns/owner=test` || rewritten[4] != `|app.example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;v=spf1\032include:example.com\032-all` {
		t.Fatalf("TXT-only startup migration got rules %v, writes %d", rewritten, writes)
	}
	records, err := p.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []*endpoint.Endpoint{{DNSName: "app.example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{`"heritage=external-dns,external-dns/owner=test"`, "v=spf1 include:example.com -all"}, Labels: endpoint.Labels{"owner": "test"}}}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("migrated TXT records got %+v, want %+v", records, want)
	}
	t.Setenv(envUseDNSRewrite, "false")
	if _, err = newInitializedTestProvider(false); err != nil {
		t.Fatal(err)
	}
	if rules, writes := a.snapshot(); !reflect.DeepEqual(rules, legacy) || writes != 2 {
		t.Fatalf("rollback got rules %v, writes %d; want %v, writes 2", rules, writes, legacy)
	}
}

func TestTXTRewriteSharesHostnameWithA(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "legacy"
		if enabled {
			name = "rewrite"
		}
		t.Run(name, func(t *testing.T) {
			c := &mockAdguardClient{}
			format := legacyRuleFormat()
			if enabled {
				format = rewriteRuleFormat()
			}
			p := &AdguardHomeProvider{client: c, ruleFormat: format}
			ctx := context.Background()
			a := &endpoint.Endpoint{DNSName: "app.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.10"}, Labels: endpoint.Labels{"kind": "address"}}
			txt := &endpoint.Endpoint{DNSName: "app.example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{"first", "second"}, Labels: endpoint.Labels{"kind": "text"}}
			if err := p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{a, txt}}); err != nil {
				t.Fatal(err)
			}
			records, err := p.Records(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(records, []*endpoint.Endpoint{a, txt}) {
				t.Fatalf("A and TXT records merged: %+v", records)
			}
			updated := &endpoint.Endpoint{DNSName: txt.DNSName, RecordType: txt.RecordType, Targets: endpoint.Targets{"updated"}, Labels: txt.Labels}
			if err = p.ApplyChanges(ctx, &plan.Changes{UpdateOld: []*endpoint.Endpoint{txt}, UpdateNew: []*endpoint.Endpoint{updated}}); err != nil {
				t.Fatal(err)
			}
			if err = p.ApplyChanges(ctx, &plan.Changes{Delete: []*endpoint.Endpoint{updated}}); err != nil {
				t.Fatal(err)
			}
			records, err = p.Records(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(records, []*endpoint.Endpoint{a}) {
				t.Fatalf("deleting TXT changed A record: %+v", records)
			}
		})
	}
}
