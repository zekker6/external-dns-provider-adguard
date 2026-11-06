package adguardhome

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
)

func rewriteRuleFormat() ruleFormat {
	return ruleFormat{
		formatRules: formatRewriteRules,
		needsMigration: func(rule string) bool {
			return !strings.HasPrefix(rule, "! ")
		},
	}
}

func formatRewriteRules(endpoints []*endpoint.Endpoint, suffix string) ([]string, error) {
	rules := make([]string, 0, 2*len(endpoints))
	for _, e := range endpoints {
		if strings.Contains(e.DNSName, "*") {
			return nil, fmt.Errorf("wildcard hostname %q is not supported in rewrite mode", e.DNSName)
		}
		rewrite, err := dnsRewriteRule(e)
		if err != nil {
			return nil, fmt.Errorf("invalid %s record for %s: %w", e.RecordType, e.DNSName, err)
		}
		// Adblock-style rules cannot carry inline ownership comments.
		metadata := "! " + endpointToString(e, suffix)
		if e.RecordType == endpoint.RecordTypeTXT {
			data, err := json.Marshal(e)
			if err != nil {
				return nil, fmt.Errorf("encode TXT metadata: %w", err)
			}
			metadata = fmt.Sprintf("! %s %s", suffix, data)
		}
		rules = append(rules, metadata, rewrite)
	}
	return rules, nil
}

func dnsRewriteRule(e *endpoint.Endpoint) (string, error) {
	value := e.Targets[0]
	if e.RecordType == endpoint.RecordTypeTXT {
		var err error
		value, err = txtRewriteValue(value)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("|%s|$dnstype=TXT,dnsrewrite=NOERROR;TXT;%s", e.DNSName, value), nil
	}
	return fmt.Sprintf("|%s|$dnsrewrite=NOERROR;%s;%s", e.DNSName, e.RecordType, value), nil
}

func txtRewriteValue(target string) (string, error) {
	if strings.ContainsAny(target, "\r\n") {
		return "", fmt.Errorf("TXT target must not contain literal line breaks")
	}

	value := target
	if strings.HasPrefix(target, `"`) {
		if len(target) < 2 || !strings.HasSuffix(target, `"`) {
			return "", fmt.Errorf("unterminated quoted TXT target")
		}
		var decoded strings.Builder
		quoted := target[1 : len(target)-1]
		for i := 0; i < len(quoted); i++ {
			b := quoted[i]
			switch b {
			case '"':
				return "", fmt.Errorf("TXT target must contain a single quoted string")
			case '\\':
				i++
				if i == len(quoted) {
					return "", fmt.Errorf("incomplete TXT escape")
				}
				b = quoted[i]
				if i+2 < len(quoted) && b >= '0' && b <= '9' && quoted[i+1] >= '0' && quoted[i+1] <= '9' && quoted[i+2] >= '0' && quoted[i+2] <= '9' {
					n, err := strconv.ParseUint(quoted[i:i+3], 10, 8)
					if err != nil {
						return "", fmt.Errorf("invalid DNS TXT escape: %w", err)
					}
					b = byte(n)
					i += 2
				}
			}
			decoded.WriteByte(b)
		}
		value = decoded.String()
	}

	// AdGuard's rewrite path emits one DNS character-string per TXT value.
	if len(value) > 255 {
		return "", fmt.Errorf("TXT value exceeds 255 bytes")
	}

	var escaped strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b <= ' ' || b >= 127 || strings.ContainsRune(",$#\"\\", rune(b)) {
			// Decimal DNS escapes survive rule parsing and avoid modifier injection.
			fmt.Fprintf(&escaped, "\\%03d", b)
		} else {
			escaped.WriteByte(b)
		}
	}
	return escaped.String(), nil
}
