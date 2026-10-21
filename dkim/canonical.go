package dkim

import (
	"io"
	"regexp"
	"strings"
)

var rxReduceWS = regexp.MustCompile(`[ \t\r\n]+`)

// Canonicalization is a canonicalization algorithm.
type Canonicalization string

const (
	CanonicalizationSimple  Canonicalization = "simple"
	CanonicalizationRelaxed                  = "relaxed"
)

type canonicalizer interface {
	CanonicalizeHeader(s string) string
	CanonicalizeBody(w io.Writer) io.WriteCloser
}

var canonicalizers = map[Canonicalization]canonicalizer{
	CanonicalizationSimple:  new(simpleCanonicalizer),
	CanonicalizationRelaxed: new(relaxedCanonicalizer),
}

// crlfFixer fixes any lone LF without a preceding CR.
type crlfFixer struct {
	cr bool
}

func (cf *crlfFixer) Fix(b []byte) []byte {
	res := make([]byte, 0, 4*len(b)/3)
	for _, ch := range b {
		prevCR := cf.cr
		cf.cr = false
		switch ch {
		case '\r':
			cf.cr = true
		case '\n':
			if !prevCR {
				res = append(res, '\r')
			}
		}
		res = append(res, ch)
	}
	return res
}

type simpleCanonicalizer struct{}

func (c *simpleCanonicalizer) CanonicalizeHeader(s string) string {
	return s
}

type simpleBodyCanonicalizer struct {
	w         io.Writer
	crlfBuf   []byte
	crlfFixer crlfFixer
}

func (c *simpleBodyCanonicalizer) Write(b []byte) (int, error) {
	written := len(b)

	if c.crlfBuf == nil {
		c.crlfBuf = make([]byte, 0, 4*len(b)/3)
	}

	b = append(c.crlfBuf, b...)

	b = c.crlfFixer.Fix(b)

	end := len(b)
	// If it ends with \r, maybe the next write will begin with \n
	if end > 0 && b[end-1] == '\r' {
		end--
	}
	// Keep all \r\n sequences
	for end >= 2 {
		prev := b[end-2]
		cur := b[end-1]
		if prev != '\r' || cur != '\n' {
			break
		}
		end -= 2
	}

	c.crlfBuf = b[end:]

	var err error
	if end > 0 {
		_, err = c.w.Write(b[:end])
	}
	return written, err
}

func (c *simpleBodyCanonicalizer) Close() error {
	// Flush crlfBuf if it ends with a single \r (without a matching \n)
	if len(c.crlfBuf) > 0 && c.crlfBuf[len(c.crlfBuf)-1] == '\r' {
		if _, err := c.w.Write(c.crlfBuf); err != nil {
			return err
		}
	}
	c.crlfBuf = nil

	if _, err := c.w.Write([]byte(crlf)); err != nil {
		return err
	}
	return nil
}

func (c *simpleCanonicalizer) CanonicalizeBody(w io.Writer) io.WriteCloser {
	return &simpleBodyCanonicalizer{w: w}
}

type relaxedCanonicalizer struct{}

func (c *relaxedCanonicalizer) CanonicalizeHeader(s string) string {
	kv := strings.SplitN(s, ":", 2)

	k := strings.TrimSpace(strings.ToLower(kv[0]))

	var v string
	if len(kv) > 1 {
		v = rxReduceWS.ReplaceAllString(kv[1], " ")
		v = strings.TrimSpace(v)

	}

	return k + ":" + v + crlf
}

// relaxedBodyBufferSize is how much canonical output is collected before it is
// written to the underlying writer. The buffer is allocated with some slack
// beyond that so that the content that crosses the threshold usually fits
// without growing the buffer.
const (
	relaxedBodyBufferSize  = 16 * 1024
	relaxedBodyBufferSlack = 1024
)

// isRelaxedBodySpecial marks the bytes that the relaxed body canonicalizer
// handles individually; every other byte is copied through unchanged.
var isRelaxedBodySpecial = [256]bool{' ': true, '\t': true, '\r': true, '\n': true}

type relaxedBodyCanonicalizer struct {
	w   io.Writer
	out []byte

	// pendingLineBreaks holds line break bytes (with any lone LF fixed to
	// CRLF) that are only written once more content follows them, which
	// drops empty lines at the end of the body.
	pendingLineBreaks []byte

	// pendingWSP is set when whitespace has been seen that will be written as
	// a single space if more content follows it on the same line.
	pendingWSP bool

	prevCR  bool
	written bool
}

func (c *relaxedBodyCanonicalizer) Write(b []byte) (int, error) {
	if c.out == nil {
		size := len(b) + len(b)/8 + 64
		if size > relaxedBodyBufferSize+relaxedBodyBufferSlack {
			size = relaxedBodyBufferSize + relaxedBodyBufferSlack
		}
		c.out = make([]byte, 0, size)
	}

	for i := 0; i < len(b); {
		switch b[i] {
		case ' ', '\t':
			c.pendingWSP = true
			c.prevCR = false
			i++

		case '\r':
			c.pendingWSP = false
			c.pendingLineBreaks = append(c.pendingLineBreaks, '\r')
			c.prevCR = true
			i++

		case '\n':
			c.pendingWSP = false
			if !c.prevCR {
				c.pendingLineBreaks = append(c.pendingLineBreaks, '\r')
			}
			c.pendingLineBreaks = append(c.pendingLineBreaks, '\n')
			c.prevCR = false
			i++

		default:
			c.prevCR = false
			c.written = true

			if len(c.pendingLineBreaks) > 0 {
				c.out = append(c.out, c.pendingLineBreaks...)
				c.pendingLineBreaks = c.pendingLineBreaks[:0]
			}
			if c.pendingWSP {
				c.out = append(c.out, ' ')
				c.pendingWSP = false
			}

			// Copy this run of ordinary bytes in one step.
			j := i + 1
			for j < len(b) && !isRelaxedBodySpecial[b[j]] {
				j++
			}
			c.out = append(c.out, b[i:j]...)
			i = j

			if len(c.out) >= relaxedBodyBufferSize {
				if err := c.flush(); err != nil {
					return 0, err
				}
			}
		}
	}

	if err := c.flush(); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *relaxedBodyCanonicalizer) flush() error {
	if len(c.out) == 0 {
		return nil
	}

	_, err := c.w.Write(c.out)
	c.out = c.out[:0]
	return err
}

func (c *relaxedBodyCanonicalizer) Close() error {
	if c.written {
		if _, err := c.w.Write([]byte(crlf)); err != nil {
			return err
		}
	}
	return nil
}

func (c *relaxedCanonicalizer) CanonicalizeBody(w io.Writer) io.WriteCloser {
	return &relaxedBodyCanonicalizer{w: w}
}

type limitedWriter struct {
	W io.Writer
	N int64
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	if w.N <= 0 {
		return len(b), nil
	}

	skipped := 0
	if int64(len(b)) > w.N {
		b = b[:w.N]
		skipped = int(int64(len(b)) - w.N)
	}

	n, err := w.W.Write(b)
	w.N -= int64(n)
	return n + skipped, err
}
