package output

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// cardBuilder turns a generic response value into one or more summary cards.
type cardBuilder func(v any) []*Card

// cardBuilders maps a view key (set by the command, e.g. "vectorsnap.ip") to a
// builder. A missing key falls back to the generic summary, so new marketplace
// APIs degrade gracefully without per-type code.
var cardBuilders = map[string]cardBuilder{}

func init() {
	for _, kind := range []string{"ip", "domain", "url", "hash"} {
		k := kind
		cardBuilders["vectorsnap."+k] = func(v any) []*Card {
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			return []*Card{buildIocCard(m, k)}
		}
		cardBuilders["pulsesnap."+k] = func(v any) []*Card {
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			return []*Card{buildPulseCard(m)}
		}
	}
	cardBuilders["subdosnap.scan"] = func(v any) []*Card {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		return []*Card{buildSubdoCard(m)}
	}
	cardBuilders["lookup"] = buildLookupCards
}

// hasCard reports whether a curated card exists for the given view.
func hasCard(view string) bool {
	_, ok := cardBuilders[view]
	return ok
}

// --------------------------------------------------------------------------
// VectorSnap (IoC reputation) card — shared across ip/domain/url/hash.
// --------------------------------------------------------------------------

func buildIocCard(v map[string]any, kind string) *Card {
	c := &Card{title: "VectorSnap · " + titleKind(kind) + " Reputation"}
	c.heading = iocIdentity(v, kind)

	malicious, total := detectionStats(v)
	c.badge, c.level = verdict(malicious, total, v)
	if total > 0 {
		c.addRow("Detections", fmt.Sprintf("%d / %d malicious", malicious, total))
	}

	c.subtitle = iocSubtitle(v, kind)

	if rep, ok := getNum(v, "reputation"); ok {
		c.addRow("Reputation", strconv.FormatInt(int64(rep), 10))
	}
	switch kind {
	case "domain":
		c.addRow("Registrar", getStr(v, "registrar"))
		c.addRow("Categories", joinList(v, "categories", 4))
	case "url":
		c.addRow("Categories", joinList(v, "categories", 4))
		c.addRow("Threats", joinList(v, "threat_names", 4))
	case "hash":
		c.addRow("Type", getStr(v, "type_description"))
		c.addRow("Name", getStr(v, "meaningful_name"))
		if sz, ok := getNum(v, "file_size"); ok {
			c.addRow("Size", humanBytes(int64(sz)))
		}
	}
	c.addRow("Tags", joinList(v, "tags", 6))

	c.footer = collectionFooter(v)
	return c
}

// iocIdentity is the primary heading for an IoC card.
func iocIdentity(v map[string]any, kind string) string {
	switch kind {
	case "ip":
		return firstNonEmpty(getStr(v, "ip"), getStr(v, "hash_id"))
	case "domain":
		return firstNonEmpty(getStr(v, "domain"), getStr(v, "hash_id"))
	case "url":
		return firstNonEmpty(getStr(v, "url"), getStr(v, "hash_id"))
	case "hash":
		return firstNonEmpty(getStr(v, "sha256"), getStr(v, "md5"), getStr(v, "hash_id"))
	default:
		return getStr(v, "hash_id")
	}
}

// iocSubtitle is the muted context line per IoC kind.
func iocSubtitle(v map[string]any, kind string) string {
	switch kind {
	case "ip":
		parts := compact(getStr(v, "as_owner"), asnStr(v), getStr(v, "country"))
		return strings.Join(parts, " · ")
	case "domain":
		return strings.Join(compact(getStr(v, "tld"), joinList(v, "categories", 3)), " · ")
	case "hash":
		return strings.Join(compact(getStr(v, "classification"), getStr(v, "type_tag")), " · ")
	default:
		return ""
	}
}

func asnStr(v map[string]any) string {
	if asn, ok := getNum(v, "asn"); ok {
		return "AS" + strconv.FormatInt(int64(asn), 10)
	}
	return ""
}

// detectionStats reads the security_vendor_analysis_stats verdict counts.
func detectionStats(v map[string]any) (malicious, total int) {
	stats, ok := getMap(v, "security_vendor_analysis_stats")
	if !ok {
		return 0, 0
	}
	for _, n := range stats {
		if f, ok := n.(float64); ok {
			total += int(f)
		}
	}
	if m, ok := stats["malicious"].(float64); ok {
		malicious = int(m)
	}
	return malicious, total
}

// verdict derives a badge from detection counts (falling back to reputation).
func verdict(malicious, total int, v map[string]any) (string, badgeLevel) {
	if total > 0 {
		switch {
		case malicious > 0:
			return "MALICIOUS", badgeMalicious
		default:
			if s, ok := getMap(v, "security_vendor_analysis_stats"); ok {
				if susp, ok := s["suspicious"].(float64); ok && susp > 0 {
					return "SUSPICIOUS", badgeSuspicious
				}
			}
			return "CLEAN", badgeClean
		}
	}
	if rep, ok := getNum(v, "reputation"); ok {
		switch {
		case rep < 0:
			return "MALICIOUS", badgeMalicious
		case rep > 0:
			return "CLEAN", badgeClean
		}
	}
	return "NO DATA", badgeNeutral
}

// --------------------------------------------------------------------------
// PulseSnap (threat-intel pulse) card.
// --------------------------------------------------------------------------

func buildPulseCard(v map[string]any) *Card {
	pd, _ := getMap(v, "pulse_detail")
	c := &Card{}
	typeTitle := firstNonEmpty(getStr(pd, "type_title"), getStr(v, "search_type"))
	c.title = "PulseSnap · " + firstNonEmpty(typeTitle, "Threat Intel")
	c.heading = firstNonEmpty(getStr(pd, "indicator"), getStr(v, "crawlsnap_hash_id"))
	c.subtitle = truncate(firstNonEmpty(getStr(pd, "title"), getStr(pd, "description")), 70)

	families := joinList(pd, "malware_families", 5)
	adversaries := joinList(pd, "adversaries", 5)
	attacks := joinList(pd, "attack_ids", 6)
	attributed := families != "" || adversaries != "" || attacks != ""
	hasData := countList(v, "malware") > 0 || countList(v, "passive_dns") > 0

	switch {
	case attributed:
		c.badge, c.level = "THREAT INTEL", badgeSuspicious
	case hasData:
		c.badge, c.level = "PULSE DATA", badgeInfo
	default:
		c.badge, c.level = "NO PULSE", badgeNeutral
	}

	c.addRow("Malware families", families)
	c.addRow("Adversaries", adversaries)
	c.addRow("MITRE ATT&CK", attacks)
	c.addRow("Targeted", joinList(pd, "targeted_countries", 5))
	c.addRow("Industries", joinList(pd, "industries", 5))
	c.addRow("Tags", joinList(pd, "tags", 6))

	c.footer = pulseFooter(v)
	return c
}

func pulseFooter(v map[string]any) string {
	var parts []string
	if n := countList(v, "malware"); n > 0 {
		parts = append(parts, fmt.Sprintf("%d malware", n))
	}
	if n := countList(v, "passive_dns"); n > 0 {
		parts = append(parts, fmt.Sprintf("%d passive DNS", n))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " · ") + "  → --full / -o json"
}

// --------------------------------------------------------------------------
// SubdoSnap (subdomain enumeration) card.
// --------------------------------------------------------------------------

func buildSubdoCard(v map[string]any) *Card {
	c := &Card{title: "SubdoSnap · Subdomains"}
	subs, _ := getSlice(v, "subdomains")
	count := len(subs)
	if cnt, ok := getNum(v, "count"); ok && int(cnt) > count {
		count = int(cnt)
	}
	c.heading = fmt.Sprintf("%d subdomains", count)
	c.badge, c.level = "FOUND", badgeInfo
	if count == 0 {
		c.badge, c.level = "NONE", badgeNeutral
	}

	const show = 12
	for i, s := range subs {
		if i >= show {
			break
		}
		name := ""
		if m, ok := s.(map[string]any); ok {
			name = getStr(m, "subdomain")
		}
		if name == "" {
			name = fmt.Sprintf("%v", s)
		}
		c.list = append(c.list, name)
	}
	if len(subs) > show {
		c.footer = fmt.Sprintf("showing %d of %d  →  --all / -o json", show, len(subs))
	} else if v["cursor"] != nil && getStr(v, "cursor") != "" {
		c.footer = "more available  →  --all"
	}
	return c
}

// --------------------------------------------------------------------------
// lookup — compose VectorSnap + PulseSnap cards (or error cards).
// --------------------------------------------------------------------------

func buildLookupCards(v any) []*Card {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	kind := getStr(m, "kind")
	var cards []*Card

	if sub, ok := getMap(m, "vectorsnap"); ok {
		if msg := getStr(sub, "error"); msg != "" {
			cards = append(cards, errorCard("VectorSnap", msg))
		} else {
			cards = append(cards, buildIocCard(sub, kind))
		}
	}
	if sub, ok := getMap(m, "pulsesnap"); ok {
		if msg := getStr(sub, "error"); msg != "" {
			cards = append(cards, errorCard("PulseSnap", msg))
		} else {
			cards = append(cards, buildPulseCard(sub))
		}
	}
	return cards
}

func errorCard(product, msg string) *Card {
	return &Card{
		title:   product,
		heading: "Error",
		badge:   "ERROR",
		level:   badgeError,
		rows:    []cardRow{{"message", truncate(msg, 80)}},
	}
}

// --------------------------------------------------------------------------
// value helpers (operate on JSON-generic maps).
// --------------------------------------------------------------------------

func getStr(v map[string]any, key string) string {
	if v == nil {
		return ""
	}
	if s, ok := v[key].(string); ok {
		return s
	}
	return ""
}

func getNum(v map[string]any, key string) (float64, bool) {
	if v == nil {
		return 0, false
	}
	f, ok := v[key].(float64)
	return f, ok
}

func getMap(v map[string]any, key string) (map[string]any, bool) {
	if v == nil {
		return nil, false
	}
	m, ok := v[key].(map[string]any)
	return m, ok
}

func getSlice(v map[string]any, key string) ([]any, bool) {
	if v == nil {
		return nil, false
	}
	s, ok := v[key].([]any)
	return s, ok
}

func countList(v map[string]any, key string) int {
	s, _ := getSlice(v, key)
	return len(s)
}

// joinList renders up to max string elements of a list field, with an overflow
// suffix. Non-string elements are skipped.
func joinList(v map[string]any, key string, max int) string {
	s, ok := getSlice(v, key)
	if !ok || len(s) == 0 {
		return ""
	}
	var items []string
	for _, e := range s {
		if str, ok := e.(string); ok && str != "" {
			items = append(items, str)
		}
	}
	if len(items) == 0 {
		return ""
	}
	if len(items) > max {
		return strings.Join(items[:max], ", ") + fmt.Sprintf(" +%d more", len(items)-max)
	}
	return strings.Join(items, ", ")
}

// collectionFooter summarizes the large array fields a card collapses, so users
// know what --full would reveal.
func collectionFooter(v map[string]any) string {
	type kv struct {
		key string
		n   int
	}
	var found []kv
	for key, val := range v {
		if s, ok := val.([]any); ok && len(s) > 0 {
			found = append(found, kv{key, len(s)})
		}
	}
	if len(found) == 0 {
		return ""
	}
	sort.Slice(found, func(i, j int) bool { return found[i].n > found[j].n })
	var parts []string
	for i, f := range found {
		if i >= 4 {
			break
		}
		parts = append(parts, fmt.Sprintf("%d %s", f.n, f.key))
	}
	return strings.Join(parts, " · ") + "  →  --full / -o json"
}

func titleKind(kind string) string {
	switch kind {
	case "ip":
		return "IP"
	case "url":
		return "URL"
	default:
		if kind == "" {
			return ""
		}
		return strings.ToUpper(kind[:1]) + kind[1:]
	}
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return ""
}

func compact(vals ...string) []string {
	var out []string
	for _, s := range vals {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
