package adguardhome

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
)

type ruleFormat struct {
	formatRules    func([]*endpoint.Endpoint, string) ([]string, error)
	needsMigration func(string) bool
}

func parseRules(rules []string, suffix string) (endpoints []*endpoint.Endpoint, unmanaged []string, err error) {
	unmanaged = make([]string, 0)
	for i := 0; i < len(rules); i++ {
		rule := strings.TrimSpace(rules[i])
		e, parseErr := parseRule(rule, suffix)
		if errors.Is(parseErr, errNotManaged) {
			unmanaged = append(unmanaged, rules[i])
			continue
		}
		if errors.Is(parseErr, errArtificialRecord) {
			continue
		}
		if parseErr != nil {
			return nil, nil, fmt.Errorf("failed to parse rule %s: %w", rule, parseErr)
		}
		if strings.HasPrefix(rule, "! ") {
			rewrite, err := dnsRewriteRule(e)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid rewrite metadata: %w", err)
			}
			if i+1 >= len(rules) {
				return nil, nil, fmt.Errorf("missing DNS rewrite after metadata: %s", rule)
			}
			active := strings.TrimSpace(rules[i+1])
			if active != rewrite {
				return nil, nil, fmt.Errorf("mismatched DNS rewrite after metadata: %s", rule)
			}
			i++
		}
		endpoints = append(endpoints, e)
	}
	return endpoints, unmanaged, nil
}

func parseRule(rule, suffix string) (*endpoint.Endpoint, error) {
	rule = strings.TrimSpace(rule)
	if data, ok := strings.CutPrefix(rule, "! "+suffix+" "); ok {
		var e endpoint.Endpoint
		if err := json.Unmarshal([]byte(data), &e); err != nil {
			return nil, fmt.Errorf("invalid TXT metadata: %w", err)
		}
		if e.RecordType != endpoint.RecordTypeTXT || e.DNSName == "" || len(e.Targets) != 1 {
			return nil, fmt.Errorf("TXT metadata must contain a hostname and one TXT target")
		}
		return &e, nil
	}
	if strings.HasPrefix(rule, "! "+managedBy) {
		return nil, errNotManaged
	}

	_, tail, managed := strings.Cut(rule, suffix)
	for managed && tail != "" {
		if strings.HasPrefix(tail, ";labels=") && json.Valid([]byte(strings.TrimPrefix(tail, ";labels="))) {
			break
		}
		_, next, found := strings.Cut(tail, suffix)
		if !found {
			break
		}
		tail = next
	}
	if !managed || (tail != "" && !strings.HasPrefix(tail, ";labels=")) {
		return nil, errNotManaged
	}
	rule = strings.TrimPrefix(rule, "! ")

	// Ignore artificial rules that we manage and will reconstruct
	if strings.HasPrefix(rule, "@@||") {
		return nil, errArtificialRecord
	}

	// Extract labels from the rule if present
	var labels endpoint.Labels
	ruleWithoutLabels := rule
	if tail != "" {
		labelsJSON := strings.TrimPrefix(tail, ";labels=")
		labels = make(endpoint.Labels)
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			log.Warnf("failed to parse labels from rule %s: %v", rule, err)
			labels = nil
		}
		ruleWithoutLabels = strings.TrimSuffix(rule, tail)
	}

	if strings.HasPrefix(rule, "#") {
		r := &endpoint.Endpoint{
			RecordType: endpoint.RecordTypeTXT,
			Labels:     labels,
		}
		content := strings.TrimSuffix(strings.TrimPrefix(ruleWithoutLabels, "# "), " "+suffix)
		separator := strings.LastIndexByte(content, ' ')
		if separator < 0 || separator == len(content)-1 {
			return nil, fmt.Errorf("invalid rule: %s", rule)
		}
		r.DNSName = content[separator+1:]
		r.Targets = endpoint.Targets{content[:separator]}

		return r, nil
	}

	parts := strings.SplitN(ruleWithoutLabels, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid rule: %s", rule)
	}

	r := &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeA,
		DNSName:    parts[1],
		Targets:    endpoint.Targets{parts[0]},
		Labels:     labels,
	}

	return r, nil
}

func endpointToString(e *endpoint.Endpoint, suffix string) string {
	// Serialize labels if present
	labelsSuffix := ""
	if len(e.Labels) > 0 {
		labelsJSON, err := json.Marshal(e.Labels)
		if err == nil {
			labelsSuffix = fmt.Sprintf(";labels=%s", string(labelsJSON))
		}
	}

	if e.RecordType == endpoint.RecordTypeTXT {
		return fmt.Sprintf("# %s %s %s%s", e.Targets[0], e.DNSName, suffix, labelsSuffix)
	}

	return fmt.Sprintf("%s %s #%s%s", e.Targets[0], e.DNSName, suffix, labelsSuffix)
}
