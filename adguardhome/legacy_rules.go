package adguardhome

import (
	"fmt"
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
)

func legacyRuleFormat() ruleFormat {
	return ruleFormat{
		formatRules: formatLegacyRules,
		needsMigration: func(rule string) bool {
			return strings.HasPrefix(rule, "! ")
		},
	}
}

func formatLegacyRules(endpoints []*endpoint.Endpoint, suffix string) ([]string, error) {
	rules := make([]string, 0, len(endpoints))
	domainSeen := make(map[string]struct{})
	domainsOrder := make([]string, 0)
	for _, e := range endpoints {
		rules = append(rules, endpointToString(e, suffix))
		if e.RecordType == endpoint.RecordTypeA {
			if _, ok := domainSeen[e.DNSName]; !ok {
				domainSeen[e.DNSName] = struct{}{}
				domainsOrder = append(domainsOrder, e.DNSName)
			}
		}
	}
	for _, d := range domainsOrder {
		rules = append(rules, artificialRuleToString(d, suffix))
	}
	return rules, nil
}

func artificialRuleToString(domain, suffix string) string {
	return fmt.Sprintf("@@||%s #%s", domain, suffix)
}
