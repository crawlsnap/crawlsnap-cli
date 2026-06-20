package output

import "testing"

func statsMap(malicious, harmless, suspicious float64) map[string]any {
	return map[string]any{
		"security_vendor_analysis_stats": map[string]any{
			"malicious":  malicious,
			"harmless":   harmless,
			"suspicious": suspicious,
		},
	}
}

func TestVerdict(t *testing.T) {
	tests := []struct {
		name      string
		v         map[string]any
		wantBadge string
		wantLevel badgeLevel
	}{
		{"malicious", statsMap(45, 20, 0), "MALICIOUS", badgeMalicious},
		{"suspicious", statsMap(0, 20, 3), "SUSPICIOUS", badgeSuspicious},
		{"clean", statsMap(0, 55, 0), "CLEAN", badgeClean},
		{"reputation negative", map[string]any{"reputation": float64(-10)}, "MALICIOUS", badgeMalicious},
		{"reputation positive", map[string]any{"reputation": float64(500)}, "CLEAN", badgeClean},
		{"no data", map[string]any{}, "NO DATA", badgeNeutral},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, total := detectionStats(tt.v)
			badge, level := verdict(m, total, tt.v)
			if badge != tt.wantBadge || level != tt.wantLevel {
				t.Errorf("verdict = (%q, %d), want (%q, %d)", badge, level, tt.wantBadge, tt.wantLevel)
			}
		})
	}
}

func TestJoinListOverflow(t *testing.T) {
	v := map[string]any{"tags": []any{"a", "b", "c", "d"}}
	got := joinList(v, "tags", 2)
	want := "a, b +2 more"
	if got != want {
		t.Errorf("joinList = %q, want %q", got, want)
	}
}
