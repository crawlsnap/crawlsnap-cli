package cmd

import "testing"

func TestDetectIndicator(t *testing.T) {
	cases := []struct {
		in   string
		want indicatorKind
	}{
		{"8.8.8.8", kindIP},
		{"2001:4860:4860::8888", kindIP},
		{"https://example.com/path", kindURL},
		{"http://example.com", kindURL},
		{"example.com", kindDomain},
		{"sub.example.co.uk", kindDomain},
		{"d41d8cd98f00b204e9800998ecf8427e", kindHash},                                 // md5
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", kindHash},                         // sha1
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", kindHash}, // sha256
		{"not a valid indicator!", kindUnknown},
		{"", kindUnknown},
	}
	for _, tc := range cases {
		if got := detectIndicator(tc.in); got != tc.want {
			t.Errorf("detectIndicator(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskKey(t *testing.T) {
	cases := map[string]string{
		"sk-cs-abcd1234": "••••••1234",
		"abcd":           "••••",
		"xy":             "••",
	}
	for in, want := range cases {
		if got := maskKey(in); got != want {
			t.Errorf("maskKey(%q) = %q, want %q", in, got, want)
		}
	}
}
