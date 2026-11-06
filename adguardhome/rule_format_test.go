package adguardhome

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestRuleFormatSelectedAtStartup(t *testing.T) {
	legacy := []string{
		"192.0.2.10 app.example.com #$managed by external-dns;ref:test",
		"# token txt.example.com $managed by external-dns;ref:test",
		"@@||app.example.com #$managed by external-dns;ref:test",
	}
	rewritten := []string{
		"! 192.0.2.10 app.example.com #$managed by external-dns;ref:test",
		"|app.example.com|$dnsrewrite=NOERROR;A;192.0.2.10",
		`! $managed by external-dns;ref:test {"dnsName":"txt.example.com","targets":["token"],"recordType":"TXT"}`,
		"|txt.example.com|$dnstype=TXT,dnsrewrite=NOERROR;TXT;token",
	}
	for _, tt := range []struct {
		name      string
		initial   string
		afterward string
		want      []string
	}{
		{name: "default", afterward: "true", want: legacy},
		{name: "legacy", initial: "false", afterward: "true", want: legacy},
		{name: "rewrite", initial: "true", afterward: "false", want: rewritten},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := setupRewriteTest(t, nil, tt.initial)
			p, err := NewAdguardHomeProvider(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.Initialize(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Setenv(envUseDNSRewrite, tt.afterward)
			ctx := context.Background()
			err = p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{
				{DNSName: "app.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.10"}},
				{DNSName: "txt.example.com", RecordType: endpoint.RecordTypeTXT, Targets: endpoint.Targets{"token"}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err = p.migrateRules(ctx); err != nil {
				t.Fatal(err)
			}
			if rules, writes := a.snapshot(); !reflect.DeepEqual(rules, tt.want) || writes != 1 {
				t.Fatalf("startup selection changed: rules=%v, writes=%d; want rules=%v, writes=1", rules, writes, tt.want)
			}
		})
	}
}

func TestRuleFormatMigrationCallbacks(t *testing.T) {
	unmanaged := []string{
		"# preserve this comment",
		"192.0.2.99 other.example.com #$managed by external-dns;ref:other",
	}
	managed := "192.0.2.10 app.example.com #$managed by external-dns;ref:test"
	original := append(append([]string(nil), unmanaged...), managed, "@@||app.example.com #$managed by external-dns;ref:test")
	for _, migrate := range []bool{false, true} {
		name := "keep current format"
		if migrate {
			name = "convert format"
		}
		t.Run(name, func(t *testing.T) {
			c := &mockAdguardClient{rules: append([]string(nil), original...)}
			checks, formats := 0, 0
			p := &AdguardHomeProvider{
				client:          c,
				managedBySuffix: "test",
				ruleFormat: ruleFormat{
					needsMigration: func(rule string) bool {
						checks++
						if rule != managed {
							t.Errorf("migration callback received unmanaged or artificial rule: %s", rule)
						}
						return migrate
					},
					formatRules: func(endpoints []*endpoint.Endpoint, suffix string) ([]string, error) {
						formats++
						want := []*endpoint.Endpoint{{DNSName: "app.example.com", RecordType: endpoint.RecordTypeA, Targets: endpoint.Targets{"192.0.2.10"}}}
						if !reflect.DeepEqual(endpoints, want) || suffix != managedBy+";ref:test" {
							t.Errorf("unexpected formatter inputs: endpoints=%v, suffix=%s", endpoints, suffix)
						}
						return []string{"# formatted by callback"}, nil
					},
				},
			}
			if err := p.migrateRules(context.Background()); err != nil {
				t.Fatal(err)
			}
			want, wantFormats := original, 0
			if migrate {
				want = append(append([]string(nil), unmanaged...), "# formatted by callback")
				wantFormats = 1
			}
			if checks != 1 || formats != wantFormats || !reflect.DeepEqual(c.rules, want) {
				t.Fatalf("migration callbacks: checks=%d, formats=%d, rules=%v; want checks=1, formats=%d, rules=%v", checks, formats, c.rules, wantFormats, want)
			}
		})
	}
}

func TestRuleFormatErrorDoesNotWrite(t *testing.T) {
	original := []string{"192.0.2.10 app.example.com #$managed by external-dns"}
	c := &mockAdguardClient{rules: append([]string(nil), original...)}
	formatErr := errors.New("formatter failed")
	formats := 0
	p := &AdguardHomeProvider{
		client: c,
		ruleFormat: ruleFormat{
			needsMigration: func(string) bool { return true },
			formatRules: func([]*endpoint.Endpoint, string) ([]string, error) {
				formats++
				return nil, formatErr
			},
		},
	}
	ctx := context.Background()
	if err := p.ApplyChanges(ctx, &plan.Changes{}); !errors.Is(err, formatErr) {
		t.Fatalf("ApplyChanges error=%v, want %v", err, formatErr)
	}
	if err := p.migrateRules(ctx); !errors.Is(err, formatErr) {
		t.Fatalf("migration error=%v, want %v", err, formatErr)
	}
	if formats != 2 || !reflect.DeepEqual(c.rules, original) {
		t.Fatalf("formatter failure changed rules: formats=%d, rules=%v", formats, c.rules)
	}
}
