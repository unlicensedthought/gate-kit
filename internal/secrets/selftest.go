// --selftest: prove each rule matches known-bad and spares known-good. A rule
// whose regex silently stops matching cannot survive this. Every bad fixture
// is composed at runtime so this file holds no credential-shaped literal.
package secrets

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

type badCase struct{ want, text string }

func fixtures() ([]badCase, []string) {
	bad := []badCase{
		{"bearer-literal", "Authorization: Bearer " + strings.Repeat("A1b2C3d4", 6) + "\n"},
		{"provider-api-key", "key = 'sk-ant-api03-" + strings.Repeat("Zq7", 12) + "'\n"},
	}
	good := []string{
		"Authorization: Bearer $GH_TOKEN\n",
		"Authorization: Bearer ${DEPLOY_TOKEN}\n",
		"Authorization: Bearer $(vault get API_TOKEN)\n",
		"OPENAI_API_KEY=sk-${OPENAI_KEY_SUFFIX}\n",
		"  integrity: sha512-" + strings.Repeat("f", 64) + "\n",
		"  resolved: https://r/x/-/x.tgz#" + strings.Repeat("a", 40) + "\n",
		"BUILD_COMMIT = 'a30a477e0'\n",
		"commit sha: " + strings.Repeat("c", 40) + "\n",
		"sha256: " + strings.Repeat("b", 64) + "\n",
	}
	return bad, good
}

func selftest(stderr io.Writer) int {
	bad, good := fixtures()
	var failures []string
	for _, c := range bad {
		got := map[string]bool{}
		for _, h := range scanText("probe.txt", c.text) {
			got[h.rule] = true
		}
		if !got[c.want] {
			ids := make([]string, 0, len(got))
			for k := range got {
				ids = append(ids, pyRepr(k))
			}
			sort.Strings(ids)
			failures = append(failures, fmt.Sprintf("KNOWN-BAD not caught by rule %s (got [%s]): %s",
				pyRepr(c.want), strings.Join(ids, ", "), pyRepr(c.text)))
		}
	}
	for _, text := range good {
		if got := scanText("probe.txt", text); len(got) > 0 {
			parts := make([]string, len(got))
			for i, h := range got {
				parts[i] = fmt.Sprintf("(%s, %d, %s, %s)", pyRepr(h.path), h.line, pyRepr(h.rule), pyRepr(h.desc))
			}
			failures = append(failures, fmt.Sprintf("KNOWN-GOOD false positive [%s]: %s",
				strings.Join(parts, ", "), pyRepr(text)))
		}
	}
	if len(failures) > 0 {
		fmt.Fprintln(stderr, tag+" SELFTEST FAILED — the regex engine is not matching:")
		for _, f := range failures {
			fmt.Fprintln(stderr, "  "+f)
		}
		return 2
	}
	fmt.Fprintf(stderr, "%s selftest OK: %d known-bad caught, %d known-good clean\n", tag, len(bad), len(good))
	return 0
}
