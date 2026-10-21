package dkim

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

var simpleCanonicalizerBodyTests = []struct {
	original  []string
	canonical string
}{
	{
		[]string{""},
		"\r\n",
	},
	{
		[]string{"\r\n"},
		"\r\n",
	},
	{
		[]string{"\r\n\r\n\r\n"},
		"\r\n",
	},
	{
		[]string{"Hey\r\n\r\n"},
		"Hey\r\n",
	},
	{
		[]string{"Hey\r\nHow r u?\r\n\r\n\r\n"},
		"Hey\r\nHow r u?\r\n",
	},
	{
		[]string{"Hey\r\n\r\nHow r u?"},
		"Hey\r\n\r\nHow r u?\r\n",
	},
	{
		[]string{"What about\nLF endings?\n\n"},
		"What about\r\nLF endings?\r\n",
	},
	{
		[]string{"\r\n", "\r", "\n"},
		"\r\n",
	},
	{
		[]string{"\r\n", "\r"},
		"\r\n\r\r\n",
	},
	{
		[]string{"\r\n", "\r", "\n", "hey\n", "\n"},
		"\r\n\r\nhey\r\n",
	},
}

func TestSimpleCanonicalizer_CanonicalBody(t *testing.T) {
	c := new(simpleCanonicalizer)

	var b bytes.Buffer
	for _, test := range simpleCanonicalizerBodyTests {
		b.Reset()

		wc := c.CanonicalizeBody(&b)
		for _, chunk := range test.original {
			if _, err := wc.Write([]byte(chunk)); err != nil {
				t.Fatalf("Expected no error while writing to simple body canonicalizer, got: %v", err)
			}
		}

		if err := wc.Close(); err != nil {
			t.Errorf("Expected no error while closing simple body canonicalizer, got: %v", err)
		} else if s := b.String(); s != test.canonical {
			t.Errorf("Expected canonical body for %q to be %q, but got %q", test.original, test.canonical, s)
		}
	}
}

var relaxedCanonicalizerHeaderTests = []struct {
	original  string
	canonical string
}{
	{
		"SubjeCT: Your Name\r\n",
		"subject:Your Name\r\n",
	},
	{
		"Subject \t:\t Your Name\t \r\n",
		"subject:Your Name\r\n",
	},
	{
		"Subject \t:\t Kimi \t \r\n No \t\r\n Na Wa\r\n",
		"subject:Kimi No Na Wa\r\n",
	},
	{
		"Subject \t:\t Ki \tmi \t \r\n No \t\r\n Na Wa\r\n",
		"subject:Ki mi No Na Wa\r\n",
	},
}

func TestRelaxedCanonicalizer_CanonicalizeHeader(t *testing.T) {
	c := new(relaxedCanonicalizer)

	for _, test := range relaxedCanonicalizerHeaderTests {
		if s := c.CanonicalizeHeader(test.original); s != test.canonical {
			t.Errorf("Expected relaxed canonical header to be %q but got %q", test.canonical, s)
		}
	}
}

var relaxedCanonicalizerBodyTests = []struct {
	original  string
	canonical string
}{
	{
		"",
		"",
	},
	{
		"\r\n",
		"",
	},
	{
		"\r\n\r\n\r\n",
		"",
	},
	{
		"Hey\r\n\r\n",
		"Hey\r\n",
	},
	{
		"Hey\r\nHow r u?\r\n\r\n\r\n",
		"Hey\r\nHow r u?\r\n",
	},
	{
		"Hey\r\n\r\nHow r u?",
		"Hey\r\n\r\nHow r u?\r\n",
	},
	{
		"Hey \t you!",
		"Hey you!\r\n",
	},
	{
		"Hey \t \r\nyou!",
		"Hey\r\nyou!\r\n",
	},
	{
		"Hey\r\n \t you!\r\n",
		"Hey\r\n you!\r\n",
	},
	{
		"Hey\r\n \t \r\n \r\n",
		"Hey\r\n",
	},
}

func TestRelaxedCanonicalizer_CanonicalBody(t *testing.T) {
	c := new(relaxedCanonicalizer)

	var b bytes.Buffer
	for _, test := range relaxedCanonicalizerBodyTests {
		b.Reset()

		wc := c.CanonicalizeBody(&b)
		if _, err := wc.Write([]byte(test.original)); err != nil {
			t.Errorf("Expected no error while writing to relaxed body canonicalizer, got: %v", err)
		} else if err := wc.Close(); err != nil {
			t.Errorf("Expected no error while closing relaxed body canonicalizer, got: %v", err)
		} else if s := b.String(); s != test.canonical {
			t.Errorf("Expected canonical body for %q to be %q, but got %q", test.original, test.canonical, s)
		}
	}
}

func TestRelaxedCanonicalizer_CanonicalBody_splitCRLF(t *testing.T) {
	want := "line 1\r\nline 2\r\n"
	writes := [][]byte{
		[]byte("line 1\r"),
		[]byte("\nline 2"),
	}

	var b bytes.Buffer
	wc := new(relaxedCanonicalizer).CanonicalizeBody(&b)
	for _, b := range writes {
		if _, err := wc.Write(b); err != nil {
			t.Errorf("Expected no error while writing to relaxed body canonicalizer, got: %v", err)
		}
	}
	if err := wc.Close(); err != nil {
		t.Errorf("Expected no error while closing relaxed body canonicalizer, got: %v", err)
	} else if s := b.String(); s != want {
		t.Errorf("Expected canonical body to be %q, but got %q", want, s)
	}
}

var relaxedCanonicalizerBodyEdgeTests = []struct {
	original  string
	canonical string
}{
	{
		"Hey\nyou!\n\n",
		"Hey\r\nyou!\r\n",
	},
	{
		"Hey\ryou!",
		"Hey\ryou!\r\n",
	},
	{
		"Hey\r\r\nyou!\r",
		"Hey\r\r\nyou!\r\n",
	},
	{
		"Hey\n\r\nyou!",
		"Hey\r\n\r\nyou!\r\n",
	},
	{
		" \t Hey",
		" Hey\r\n",
	},
	{
		"Hey \t ",
		"Hey\r\n",
	},
	{
		"a\tb  c \t d",
		"a b c d\r\n",
	},
	{
		"\r\n \r\n\t\r\nHey",
		"\r\n\r\n\r\nHey\r\n",
	},
	{
		"=3D\"x\" =\r\n  <td>\r\n",
		"=3D\"x\" =\r\n <td>\r\n",
	},
}

func canonicalizeRelaxedBody(t *testing.T, writes ...string) string {
	t.Helper()

	var b bytes.Buffer
	wc := new(relaxedCanonicalizer).CanonicalizeBody(&b)
	for _, w := range writes {
		if n, err := wc.Write([]byte(w)); err != nil {
			t.Fatalf("Expected no error while writing to relaxed body canonicalizer, got: %v", err)
		} else if n != len(w) {
			t.Fatalf("Expected relaxed body canonicalizer to report writing %d bytes, got %d", len(w), n)
		}
	}
	if err := wc.Close(); err != nil {
		t.Fatalf("Expected no error while closing relaxed body canonicalizer, got: %v", err)
	}
	return b.String()
}

func TestRelaxedCanonicalizer_CanonicalBody_edgeCases(t *testing.T) {
	for _, test := range relaxedCanonicalizerBodyEdgeTests {
		if s := canonicalizeRelaxedBody(t, test.original); s != test.canonical {
			t.Errorf("Expected canonical body for %q to be %q, but got %q", test.original, test.canonical, s)
		}
	}
}

// Splitting the body across two writes at any position must not change the result.
func TestRelaxedCanonicalizer_CanonicalBody_everySplit(t *testing.T) {
	tests := append(append([]struct {
		original  string
		canonical string
	}{}, relaxedCanonicalizerBodyTests...), relaxedCanonicalizerBodyEdgeTests...)

	for _, test := range tests {
		for i := 0; i <= len(test.original); i++ {
			if s := canonicalizeRelaxedBody(t, test.original[:i], test.original[i:]); s != test.canonical {
				t.Errorf("Expected canonical body for %q split at %d to be %q, but got %q", test.original, i, test.canonical, s)
			}
		}
	}
}

func TestRelaxedCanonicalizer_CanonicalBody_large(t *testing.T) {
	original := strings.Repeat("Hey  \t you! \n", 10000) + "\n\n"
	want := strings.Repeat("Hey you!\r\n", 10000)

	if s := canonicalizeRelaxedBody(t, original); s != want {
		t.Errorf("Expected large canonical body to be %d bytes of repeated lines, but got %d bytes", len(want), len(s))
	}
}

func BenchmarkRelaxedCanonicalizer_CanonicalBody(b *testing.B) {
	line := "<td class=3D\"content\" style=3D\"color: #333;\">   Hey \t you! =\r\n"
	body := []byte(strings.Repeat(line, 80000/len(line)) + "\r\n\r\n")

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		wc := new(relaxedCanonicalizer).CanonicalizeBody(ioutil.Discard)
		wc.Write(body)
		wc.Close()
	}
}
