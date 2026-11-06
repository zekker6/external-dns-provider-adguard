package adguardhome

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

type rewriteTestAPI struct {
	t      *testing.T
	mu     sync.Mutex
	rules  []string
	writes int
}

func (a *rewriteTestAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/control/status":
		if err := json.NewEncoder(w).Encode(struct{}{}); err != nil {
			a.t.Errorf("encode status: %v", err)
		}
	case "/control/filtering/status":
		if err := json.NewEncoder(w).Encode(filteringStatus{UserRules: a.rules}); err != nil {
			a.t.Errorf("encode filtering status: %v", err)
		}
	case "/control/filtering/set_rules":
		var body setRules
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.rules = body.Rules
		a.writes++
	default:
		http.NotFound(w, r)
	}
}

func (a *rewriteTestAPI) snapshot() ([]string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.rules...), a.writes
}

func setupRewriteTest(t *testing.T, rules []string, flag string) *rewriteTestAPI {
	t.Helper()
	a := &rewriteTestAPI{t: t, rules: append([]string(nil), rules...)}
	s := httptest.NewServer(a)
	t.Cleanup(s.Close)
	t.Setenv(envURL, s.URL)
	t.Setenv(envUser, "test-user")
	t.Setenv(envPassword, "test-password")
	t.Setenv(envManagedBy, "test")
	t.Setenv("ADGUARD_HOME_USE_DNSREWRITE", flag)
	return a
}

func newInitializedTestProvider(dryRun bool) (*AdguardHomeProvider, error) {
	p, err := NewAdguardHomeProvider(context.Background(), dryRun)
	if err != nil {
		return nil, err
	}
	if err = p.Initialize(context.Background()); err != nil {
		return nil, err
	}
	return p, nil
}

func TestDNSRewriteMigration(t *testing.T) {
	unmanaged := []string{
		"# User comment",
		"192.0.2.99 unmanaged.example.com",
		"192.0.2.98 other.example.com #$managed by external-dns;ref:other",
		"192.0.2.96 prefix-owner.example.com #$managed by external-dns;ref:test-other",
		"! 192.0.2.97 other-rewrite.example.com #$managed by external-dns;ref:other",
		"|other-rewrite.example.com|$dnsrewrite=NOERROR;A;192.0.2.97",
		`! $managed by external-dns;ref:other {"dnsName":"other-txt.example.com","targets":["$managed by external-dns;ref:test;labels=not-json"],"recordType":"TXT"}`,
		`|other-txt.example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;\036managed\032by\032external-dns;ref:test;labels=not-json`,
	}
	legacy := append(append([]string(nil), unmanaged...),
		`192.0.2.10 app.example.com #$managed by external-dns;ref:test;labels={"owner":"test"}`,
		`192.0.2.11 app.example.com #$managed by external-dns;ref:test;labels={"owner":"test"}`,
		"# ownership txt.example.com $managed by external-dns;ref:test",
		"@@||app.example.com #$managed by external-dns;ref:test",
	)
	rewritten := append(append([]string(nil), unmanaged...),
		`! 192.0.2.10 app.example.com #$managed by external-dns;ref:test;labels={"owner":"test"}`,
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.10",
		`! 192.0.2.11 app.example.com #$managed by external-dns;ref:test;labels={"owner":"test"}`,
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.11",
		`! $managed by external-dns;ref:test {"dnsName":"txt.example.com","targets":["ownership"],"recordType":"TXT"}`,
		"|txt.example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;ownership",
	)

	for _, tt := range []struct {
		name   string
		flag   string
		before []string
		after  []string
		writes int
	}{
		{name: "default remains legacy", before: legacy, after: legacy},
		{name: "explicit false remains legacy", flag: "false", before: legacy, after: legacy},
		{name: "migrate on startup without DNS changes", flag: "true", before: legacy, after: rewritten, writes: 1},
		{name: "already migrated", flag: "true", before: rewritten, after: rewritten},
		{name: "rollback", flag: "false", before: rewritten, after: legacy, writes: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := setupRewriteTest(t, tt.before, tt.flag)
			p, err := newInitializedTestProvider(false)
			if err != nil {
				t.Fatal(err)
			}
			rules, writes := a.snapshot()
			if !reflect.DeepEqual(rules, tt.after) || writes != tt.writes {
				t.Fatalf("migration got rules %v, writes %d; want rules %v, writes %d", rules, writes, tt.after, tt.writes)
			}
			records, err := p.Records(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := []*endpoint.Endpoint{
				{DNSName: "app.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.10", "192.0.2.11"}, Labels: endpoint.Labels{"owner": "test"}},
				{DNSName: "txt.example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{"ownership"}},
			}
			if !reflect.DeepEqual(records, want) {
				t.Fatalf("records got %+v, want %+v", records, want)
			}
			if err = p.ApplyChanges(context.Background(), &plan.Changes{}); err != nil {
				t.Fatal(err)
			}
			rules, _ = a.snapshot()
			if !reflect.DeepEqual(rules, tt.after) {
				t.Fatalf("reconciliation lost or changed rules: got %v, want %v", rules, tt.after)
			}
		})
	}
}

func TestDNSRewriteMixedSyntax(t *testing.T) {
	a := setupRewriteTest(t, []string{
		"192.0.2.10 app.example.com #$managed by external-dns;ref:test",
		"! 192.0.2.11 app.example.com #$managed by external-dns;ref:test",
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.11",
		"@@||app.example.com #$managed by external-dns;ref:test",
	}, "true")
	if _, err := newInitializedTestProvider(false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"! 192.0.2.10 app.example.com #$managed by external-dns;ref:test",
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.10",
		"! 192.0.2.11 app.example.com #$managed by external-dns;ref:test",
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.11",
	}
	if rules, writes := a.snapshot(); !reflect.DeepEqual(rules, want) || writes != 1 {
		t.Fatalf("mixed migration got %v, writes %d; want %v, writes 1", rules, writes, want)
	}
}

func TestDNSRewriteDefaultOwner(t *testing.T) {
	otherOwner := "192.0.2.99 other.example.com #$managed by external-dns;ref:other"
	a := setupRewriteTest(t, []string{
		otherOwner,
		"192.0.2.10 app.example.com #$managed by external-dns",
	}, "true")
	t.Setenv(envManagedBy, "")
	if _, err := newInitializedTestProvider(false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		otherOwner,
		"! 192.0.2.10 app.example.com #$managed by external-dns",
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.10",
	}
	if rules, _ := a.snapshot(); !reflect.DeepEqual(rules, want) {
		t.Fatalf("default owner migration got %v, want %v", rules, want)
	}
}

func TestDNSRewriteApplyChanges(t *testing.T) {
	a := setupRewriteTest(t, nil, "true")
	p, err := newInitializedTestProvider(false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	original := &endpoint.Endpoint{DNSName: "app.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.10", "192.0.2.11"}, Labels: endpoint.Labels{"owner": "test"}}
	if err = p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{original}}); err != nil {
		t.Fatal(err)
	}
	updated := &endpoint.Endpoint{DNSName: "app.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.12"}, Labels: original.Labels}
	if err = p.ApplyChanges(ctx, &plan.Changes{UpdateOld: []*endpoint.Endpoint{original}, UpdateNew: []*endpoint.Endpoint{updated}}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`! 192.0.2.12 app.example.com #$managed by external-dns;ref:test;labels={"owner":"test"}`,
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.12",
	}
	if rules, _ := a.snapshot(); !reflect.DeepEqual(rules, want) {
		t.Fatalf("update got %v, want %v", rules, want)
	}
	if err = p.ApplyChanges(ctx, &plan.Changes{Delete: []*endpoint.Endpoint{updated}}); err != nil {
		t.Fatal(err)
	}
	if rules, _ := a.snapshot(); len(rules) != 0 {
		t.Fatalf("delete left rules %v", rules)
	}
}

func TestDNSRewriteInvalidFlag(t *testing.T) {
	a := setupRewriteTest(t, nil, "not-a-bool")
	if _, err := NewAdguardHomeProvider(context.Background(), false); err == nil {
		t.Fatal("expected invalid flag to fail startup")
	}
	if _, writes := a.snapshot(); writes != 0 {
		t.Fatal("invalid flag must not write rules")
	}
}

func TestDNSRewriteDryRun(t *testing.T) {
	original := []string{
		"192.0.2.10 app.example.com #$managed by external-dns;ref:test",
		"# ownership txt.example.com $managed by external-dns;ref:test",
	}
	a := setupRewriteTest(t, original, "true")
	p, err := newInitializedTestProvider(true)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.ApplyChanges(context.Background(), &plan.Changes{}); err != nil {
		t.Fatal(err)
	}
	if rules, writes := a.snapshot(); !reflect.DeepEqual(rules, original) || writes != 0 {
		t.Fatalf("dry run changed rules: %v, writes %d", rules, writes)
	}
}

func TestDNSRewriteInvalidPair(t *testing.T) {
	for _, rules := range [][]string{
		{"! 192.0.2.10 app.example.com #$managed by external-dns;ref:test"},
		{"! 192.0.2.10 app.example.com #$managed by external-dns;ref:test", "|different.example.com|$dnsrewrite=NOERROR;A;192.0.2.10"},
		{`! $managed by external-dns;ref:test {"dnsName":"txt.example.com","targets":["token"],"recordType":"TXT"}`},
		{`! $managed by external-dns;ref:test {"dnsName":"txt.example.com","targets":["token"],"recordType":"TXT"}`, "|txt.example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;different"},
		{`! $managed by external-dns;ref:test {"dnsName":"txt.example.com","targets":[],"recordType":"TXT"}`},
		{`! $managed by external-dns;ref:test {invalid-json}`},
	} {
		t.Run(rules[0], func(t *testing.T) {
			a := setupRewriteTest(t, rules, "true")
			p, err := newInitializedTestProvider(false)
			if err == nil {
				_, err = p.Records(context.Background())
			}
			if err == nil {
				t.Fatal("expected incomplete or mismatched metadata pair to fail")
			}
			if _, writes := a.snapshot(); writes != 0 {
				t.Fatal("invalid metadata pair must not overwrite rules")
			}
		})
	}
}
