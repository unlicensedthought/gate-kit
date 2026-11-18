// Python `re` / `str` semantics the gate was specified against, rebuilt on Go.
// The rules were written for Python 3's str regexes, where \s, \w and \b are
// Unicode-aware and IGNORECASE folds a few characters Go's (?i) does not.
// Go's \s is ASCII and omits \v; Go's \b is ASCII-only. Each helper here
// spells out the Python behaviour so a line Python scanned is scanned here.
package secrets

import (
	"strings"
	"unicode"
)

// pyWS is Python's str \s: str.isspace(), i.e. bidi types WS/B/S plus Zs.
// Go's \s would miss \v, \x1c-\x1f, NEL, NBSP and the Unicode spaces.
const pyWS = `[\t\n\v\f\r \x1c-\x1f\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

// pyFoldI rewrites an ASCII literal for use inside a (?i) Go pattern so the
// letter i also matches U+0130 and U+0131, as Python's IGNORECASE does. Go's
// (?i) already folds k/U+212A and s/U+017F, Python's other two ASCII extras.
// Non-letters are regexp-quoted.
func pyFoldI(lit string) string {
	var b strings.Builder
	for _, r := range lit {
		switch {
		case r == 'i' || r == 'I':
			b.WriteString(`[iI\x{130}\x{131}]`)
		case r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'):
			b.WriteRune(r)
		default:
			b.WriteString(regexpQuoteRune(r))
		}
	}
	return b.String()
}

// pyFold lower-cases ASCII and maps the four non-ASCII runes that Python's
// IGNORECASE (and pyFoldI) equate with an ASCII letter: U+017F->s,
// U+212A->k, U+0130->i, U+0131->i. A (?i) pattern built from ASCII literals
// can match a line only if pyFold(line) contains the lower-cased literal, which
// makes this a sound prefilter.
func pyFold(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case 0x17f:
			r = 's'
		case 0x212a:
			r = 'k'
		case 0x130, 0x131:
			r = 'i'
		default:
			if r < 0x80 && r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

func regexpQuoteRune(r rune) string {
	if strings.ContainsRune(`\.+*?()|[]{}^$-`, r) {
		return `\` + string(r)
	}
	return string(r)
}

// isPyWord is Python's str \w: str.isalnum() or '_'. isalnum is
// isalpha (L*) or isdecimal/isdigit/isnumeric (Nd, Nl, No and the few other
// Numeric_Type code points, which are letters already).
func isPyWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// splitLines is Python's str.splitlines(): it breaks on \n, \r, \r\n, \v, \f,
// \x1c, \x1d, \x1e, \x85, U+2028 and U+2029, and a trailing terminator does not
// produce an empty final line.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		w := 0
		switch {
		case c == '\r':
			w = 1
			if i+1 < len(s) && s[i+1] == '\n' {
				w = 2
			}
		case c == '\n' || c == '\v' || c == '\f' || c == 0x1c || c == 0x1d || c == 0x1e:
			w = 1
		case c == 0xc2 && i+1 < len(s) && s[i+1] == 0x85:
			w = 2
		case c == 0xe2 && i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xa8 || s[i+2] == 0xa9):
			w = 3
		}
		if w == 0 {
			i++
			continue
		}
		out = append(out, s[start:i])
		i += w
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// pyRepr renders a string the way Python's repr() does, for the diagnostics
// that quote a path or a fixture. Only the escapes those texts can contain are
// handled: quotes, backslash, \n \r \t and other C0 controls.
func pyRepr(s string) string {
	q := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == rune(q):
			b.WriteByte('\\')
			b.WriteByte(q)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\x`)
			b.WriteString(strings.ToLower(hex2(byte(r))))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

func hex2(c byte) string {
	const h = "0123456789abcdef"
	return string([]byte{h[c>>4], h[c&15]})
}
