package leak

import "testing"

// SVG path coordinates are not phone numbers; real formats still are.
func TestPhoneHitSkipsDecimalCoordinates(t *testing.T) {
	for _, s := range []string{
		`d="M308.064 1000C318.837 1074 308.805 1071 289.787 1059"`,
		"scale 0.666667 0.666992 263.423 " + "1164.5",
		"v1.234.5678 and 12.345.6789",
		"build 1.555.123." + "4567",   // a longer dotted number, not a phone
		"ref 555-123-" + "4567.89 ok", // a decimal fraction after the match
	} {
		if phoneHit(s) {
			t.Errorf("false positive on %q", s)
		}
	}
	for _, s := range []string{
		"call (555) 123-" + "4567", "call (555)123-" + "4567", "call 555-123-" + "4567",
		"call 555.123." + "4567", "call 555 123 " + "4567", "tel:555-123-" + "4567.",
	} {
		if !phoneHit(s) {
			t.Errorf("missed a phone number in %q", s)
		}
	}
}

// The regex alone flags SVG path data. This pins why
// phoneHit exists: if the raw regex stops matching these, the extra checks are dead code.
func TestRawPhoneRegexMatchesCoordinates(t *testing.T) {
	for _, s := range []string{
		`d="M308.064 1000C318.837 1074 308.805 1071 289.787 1059"`,
		"scale 0.666667 0.666992 263.423 " + "1164.5",
	} {
		if !phoneRe.MatchString(s) {
			t.Errorf("the raw regex no longer matches %q; phoneHit's extra checks guard nothing", s)
		}
	}
}
