package tokenurl

// THIS IS A SPEED-BUMP, NOT A BOUNDARY.
//
// It reads source text and pattern-matches the shape of an embedded git
// credential. That is a losing game: an earlier version was defeated in
// consecutive adversarial rounds, and each time the fix was a bigger regex.
// What it is for is stopping the bad pattern from being committed and then
// copy-pasted onward. The real boundary is a credential helper that hands git
// the secret on stdin, so nobody has a reason to put one in a command line.
//
// It works on logical lines (backslash continuations joined), is
// case-insensitive on git config keys, follows one hop of variable taint, and
// classifies a URL by the shape of its userinfo.
//
// DETECTED
//
//	A  git invoked with a URL whose userinfo carries credential material: a
//	   shell interpolation, a known token prefix, or any non-empty user:secret@
//	   pair that is not a <...> documentation stand-in.
//	B  a variable assigned such a URL.
//	C  git invoked with a variable tainted by B (whole file, order-independent).
//	D  a shell-executed credential.helper value: !snippet, an absolute path
//	   with arguments, or a value naming an interpreter. A bare path with no
//	   arguments, the sanctioned wiring, is not flagged.
//	E  http.extraHeader = Authorization..., any case, leading whitespace allowed. token-in-url-gate:allow
//
// NOT DETECTED, and recorded as such in testdata/evasions.json (the selftest
// fails if a recorded miss starts being caught or a recorded catch is lost):
//
//   - nested command substitution
//   - quotes inside the userinfo, or a token literal split by adjacent quoting
//   - a header value produced by a command substitution, so the banned word
//     never appears in the source
//   - multi-step string assembly, arrays, eval, encoded URLs, a token written
//     to a file git later reads, a wrapper function that execs git
//   - anything never committed, and anyone who runs `git commit --no-verify`
//
// A line carrying the marker `token-url:allow` is skipped; on a continuation
// the marker on any constituent line skips the whole logical line.
