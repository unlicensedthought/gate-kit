package tokenurl

// pytext.go: the Python text semantics the original engine leaned on without
// saying so, reproduced by hand because Go's defaults differ on every one:
//
//   - `\s`, str.strip(), str.split(): Python's Unicode whitespace set (29 code
//     points, enumerated from CPython 3.9 below). Go's `\s` is 6 ASCII bytes.
//   - `\w` / `\b`: Unicode letters, numbers and '_' (CPython 3.9's `\w` is
//     exactly [\p{L}\p{N}_]; verified by enumerating every code point). Go's
//     `\w` is ASCII and RE2 has no Unicode `\b`.
//   - str.splitlines(): splits on ten line boundaries, not just "\n".
//   - text-mode reads: undecodable bytes become U+FFFD per Unicode "maximal
//     subpart" (errors="replace"), and \r\n / \r become \n (universal newlines).
//   - str slicing ([:200]) counts code points, not bytes.
//   - %r of a str.

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// pyWSClass is Python's `\s` as an RE2 character-class body.
const pyWSClass = `\t\n\v\f\r\x1c-\x1f \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`

// isPyWS reports whether r is in Python's `\s` (== str.isspace()).
func isPyWS(r rune) bool {
	switch {
	case r >= '\t' && r <= '\r', r >= 0x1c && r <= 0x20, r == 0x85, r == 0xa0, r == 0x1680,
		r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}

// isPyWord reports whether r is in Python's `\w`.
func isPyWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// pyStrip is str.strip() with no argument.
func pyStrip(s string) string { return strings.TrimFunc(s, isPyWS) }

// pyRStrip is str.rstrip() with no argument.
func pyRStrip(s string) string { return strings.TrimRightFunc(s, isPyWS) }

// pyFields is str.split() with no argument.
func pyFields(s string) []string { return strings.FieldsFunc(s, isPyWS) }

// isLineBoundary is the set str.splitlines() splits on ("\r\n" is one boundary).
func isLineBoundary(r rune) bool {
	switch r {
	case '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// pySplitlines is str.splitlines() (keepends=False).
func pySplitlines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !isLineBoundary(r) {
			i += size
			continue
		}
		out = append(out, s[start:i])
		i += size
		if r == '\r' && i < len(s) && s[i] == '\n' {
			i++
		}
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// pyDecode reproduces Python's text-mode read: UTF-8 with errors="replace"
// (one U+FFFD per maximal invalid subpart, as CPython emits) followed by
// universal-newline translation.
func pyDecode(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); {
		c := b[i]
		if c < utf8.RuneSelf {
			sb.WriteByte(c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			sb.Write(b[i : i+size])
			i += size
			continue
		}
		need, lo, hi := 0, byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need = 1
		case c == 0xe0:
			need, lo = 2, 0xa0
		case c == 0xed:
			need, hi = 2, 0x9f
		case c >= 0xe1 && c <= 0xef:
			need = 2
		case c == 0xf0:
			need, lo = 3, 0x90
		case c == 0xf4:
			need, hi = 3, 0x8f
		case c >= 0xf1 && c <= 0xf3:
			need = 3
		}
		k := 1
		for j := 0; j < need && i+k < len(b); j++ {
			x := b[i+k]
			if j == 0 && (x < lo || x > hi) || j > 0 && (x < 0x80 || x > 0xbf) {
				break
			}
			k++
		}
		sb.WriteRune(utf8.RuneError)
		i += k
	}
	s := sb.String()
	if strings.IndexByte(s, '\r') >= 0 {
		s = strings.ReplaceAll(s, "\r\n", "\n")
		s = strings.ReplaceAll(s, "\r", "\n")
	}
	return s
}

// runePrefix is Python's s[:n] on a str.
func runePrefix(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// pyRepr is repr() of a str.
func pyRepr(s string) string {
	q := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		q = '"'
	}
	var sb strings.Builder
	sb.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case r == '\t':
			sb.WriteString(`\t`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			sb.WriteString(`\x` + pad(strconv.FormatInt(int64(r), 16), 2))
		case r < 0x7f || unicode.IsPrint(r):
			sb.WriteRune(r)
		case r <= 0xff:
			sb.WriteString(`\x` + pad(strconv.FormatInt(int64(r), 16), 2))
		case r <= 0xffff:
			sb.WriteString(`\u` + pad(strconv.FormatInt(int64(r), 16), 4))
		default:
			sb.WriteString(`\U` + pad(strconv.FormatInt(int64(r), 16), 8))
		}
	}
	sb.WriteByte(q)
	return sb.String()
}

func pad(h string, n int) string {
	for len(h) < n {
		h = "0" + h
	}
	return h
}
