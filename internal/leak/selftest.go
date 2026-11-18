package leak

import (
	"fmt"
	"io"
)

// selftest proves every detector fires on a known-bad line and spares known-good ones.
func selftest(stderr io.Writer) int {
	e := &engine{terms: []string{"zorblax"}, pii: map[string]bool{"email": true, "us-phone": true, "ssn": true}}
	bad := map[string]string{
		"private-term #1":        "we met with Zorblax today",
		"PII: email address":     "mail jane.roe" + "@gmail.com now",
		"PII: US phone number":   "call (555) 123-" + "4567",
		"PII: SSN-shaped number": "id 123-45-6789", // gate:allow-line: test fixture
	}
	good := []string{
		"mail ops@example.com", "from noreply@corp.invalid", "zorblaxian is not the term",
		"call 5551234 only", "fixture 123-45-6789 gate:allow-line",
	}
	fail := 0
	for want, text := range bad {
		hit := false
		for _, f := range e.scan("x.txt", []byte(text+"\n")) {
			hit = hit || f.rule == want
		}
		if !hit {
			fmt.Fprintf(stderr, "gate-kit leak selftest: %q not caught\n", want)
			fail = 2
		}
	}
	for _, text := range good {
		// the pragma line is exempt from PII shapes only, never from the term list
		if fs := e.scan("x.txt", []byte(text+"\n")); len(fs) > 0 {
			fmt.Fprintf(stderr, "gate-kit leak selftest: false positive on %q: %v\n", text, fs)
			fail = 2
		}
	}
	if len(e.scan("x.txt", []byte("Zorblax gate:allow-line\n"))) == 0 {
		fmt.Fprintln(stderr, "gate-kit leak selftest: the pragma exempted a private term")
		fail = 2
	}
	if fail == 0 {
		fmt.Fprintln(stderr, "gate-kit leak selftest OK")
	}
	return fail
}
