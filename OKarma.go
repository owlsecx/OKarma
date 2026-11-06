// OKarma — Evil-Twin/KARMA Analyzer
// Author  : khaled.s.haddad
// Website : owlsec.org
// Language: Go (stdlib only, static, CGO disabled)
// OWL Security Tools — Batch 3 (Wireless). Authorized testing only.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const APPNAME = "OKarma"
const SUITE = "Owl Wireless Suite"
const TAGLINE = "Evil-Twin/KARMA Analyzer"
const SUBLINE = "Beacons · Probe responses · KARMA · RSN/WPA · EAPOL · Rogue-AP detection"
const VERSION = "3.1.0"
const CATEGORY = "OWireless"
const MITRE = "T1557.002, T1557, T1598"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

const BANNER = `
 ██████╗ ██╗  ██╗ █████╗ ██████╗ ███╗   ███╗ █████╗ 
██╔═══██╗██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗
██║   ██║█████╔╝ ███████║██████╔╝██╔████╔██║███████║
██║   ██║██╔═██╗ ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║
╚██████╔╝██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	DR  = "\033[96m" // legacy frame alias → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func line(w int)       { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", B, R) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW) + col("   ·   MITRE "+MITRE, DIM))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Printf("  %s  %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(it, W))
	}
	fmt.Println()
	fmt.Println("  " + col("[H]", YLW+B) + "  " + col("Help & Usage", W) + col("  — how to use, options, CLI flags & examples", DIM))
	fmt.Println("  " + col("[0]", R+B) + "  " + col("Exit", W))
	fmt.Println()
	rule()
	return prompt("Select option")
}
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ============================================================================
//  OWL shared core — formatting, grading, numeric + byte helpers
// ============================================================================

var startedAt = time.Now()

func appVersion() string { return VERSION }

// sectionHeader prints a colored section heading used by help/howto/report views.
func sectionHeader(s string) {
	fmt.Println()
	fmt.Println("  " + col("⬡  "+s, CY+B))
	line(64)
}

func subHeader(s string) { fmt.Println("  " + col("» "+s, CY+B)) }

func kvRow(k, v string) {
	fmt.Println("  " + col(pad(k, 22), GY) + col(v, W))
}

func bullet(s string) { fmt.Println("   " + col("•", CY) + " " + col(s, W)) }

func numbered(i int, s string) {
	fmt.Println("   " + col(fmt.Sprintf("%2d.", i), CY+B) + " " + col(s, W))
}

// hr draws a plain separator (no ANSI) for exported text reports.
func hr(w int) string { return strings.Repeat("-", w) }

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------------------------------------------------------------------------
//  Grading engine (A+ .. F) based on a 0..100 posture/quality score.
// ---------------------------------------------------------------------------

func gradeFromScore(score float64) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 67:
		return "D+"
	case score >= 63:
		return "D"
	case score >= 60:
		return "D-"
	default:
		return "F"
	}
}

func gradeColor(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return GRN + B
	case strings.HasPrefix(g, "B"):
		return GRN
	case strings.HasPrefix(g, "C"):
		return YLW
	case strings.HasPrefix(g, "D"):
		return R
	default:
		return R + B
	}
}

func gradeLabel(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return "Excellent posture"
	case strings.HasPrefix(g, "B"):
		return "Good posture, minor gaps"
	case strings.HasPrefix(g, "C"):
		return "Fair, several weaknesses"
	case strings.HasPrefix(g, "D"):
		return "Poor, material exposure"
	default:
		return "Critical exposure"
	}
}

// ---------------------------------------------------------------------------
//  Severity model
// ---------------------------------------------------------------------------

const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical:
		return R + B
	case SevHigh:
		return R
	case SevMedium:
		return YLW
	case SevLow:
		return W
	default:
		return GY
	}
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return SevCritical
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMedium
	case score >= 0.1:
		return SevLow
	default:
		return SevInfo
	}
}

// sarifLevel maps severity to SARIF result levels.
func sarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow:
		return "note"
	}
	return "none"
}

// ---------------------------------------------------------------------------
//  Numeric / statistics helpers
// ---------------------------------------------------------------------------

func meanF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddevF(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := meanF(xs)
	s := 0.0
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(xs)-1))
}

func minF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func maxF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func percentileF(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	idx := int(clamp(p/100.0*float64(len(cp)-1), 0, float64(len(cp)-1)) + 0.5)
	return cp[idx]
}

// shannonEntropy returns bits/byte entropy of a buffer (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	e := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}

// ---------------------------------------------------------------------------
//  Byte reader with endian-aware helpers
// ---------------------------------------------------------------------------

type byteReader struct {
	b   []byte
	pos int
	le  bool
}

func newReader(b []byte, le bool) *byteReader { return &byteReader{b: b, le: le} }

func (r *byteReader) remaining() int { return len(r.b) - r.pos }
func (r *byteReader) eof() bool      { return r.pos >= len(r.b) }

func (r *byteReader) u8() (uint8, bool) {
	if r.pos+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

func (r *byteReader) u16() (uint16, bool) {
	if r.pos+2 > len(r.b) {
		return 0, false
	}
	var v uint16
	if r.le {
		v = binary.LittleEndian.Uint16(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint16(r.b[r.pos:])
	}
	r.pos += 2
	return v, true
}

func (r *byteReader) u32() (uint32, bool) {
	if r.pos+4 > len(r.b) {
		return 0, false
	}
	var v uint32
	if r.le {
		v = binary.LittleEndian.Uint32(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint32(r.b[r.pos:])
	}
	r.pos += 4
	return v, true
}

func (r *byteReader) u64() (uint64, bool) {
	if r.pos+8 > len(r.b) {
		return 0, false
	}
	var v uint64
	if r.le {
		v = binary.LittleEndian.Uint64(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint64(r.b[r.pos:])
	}
	r.pos += 8
	return v, true
}

func (r *byteReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, true
}

func (r *byteReader) skip(n int) bool {
	if r.pos+n > len(r.b) || n < 0 {
		return false
	}
	r.pos += n
	return true
}

func (r *byteReader) align(n int) {
	if n <= 1 {
		return
	}
	if m := r.pos % n; m != 0 {
		r.pos += n - m
	}
}

// ============================================================================
//  Hex dump loader — tolerant of xxd / tcpdump / wireshark / raw hex layouts
// ============================================================================

// parseHexDump extracts raw bytes from assorted textual hex representations.
// It strips offsets (leading "0000  "), ASCII side panes, 0x prefixes, commas
// and whitespace, then decodes the remaining hex nibbles.
func parseHexDump(s string) ([]byte, error) {
	var out []byte
	lines := strings.Split(s, "\n")
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		if t := strings.TrimSpace(ln); t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		// Drop a trailing ASCII pane after 2+ spaces or a '|' guard.
		if i := strings.Index(ln, "  |"); i >= 0 {
			ln = ln[:i]
		}
		fields := strings.Fields(ln)
		// Heuristic: if first field looks like an offset (hex, len>=4, no more
		// hex pairs resembling it), drop it.
		if len(fields) > 1 && looksLikeOffset(fields[0]) {
			fields = fields[1:]
		}
		for _, f := range fields {
			f = strings.TrimPrefix(f, "0x")
			f = strings.TrimPrefix(f, "0X")
			f = strings.TrimSuffix(f, ",")
			f = strings.TrimSuffix(f, ":")
			f = strings.TrimSuffix(f, "h")
			if f == "" {
				continue
			}
			// a chunk may be a run of nibbles with colons (aa:bb:cc)
			f = strings.ReplaceAll(f, ":", "")
			f = strings.ReplaceAll(f, "-", "")
			if !isHexRun(f) {
				continue
			}
			if len(f)%2 == 1 {
				// odd nibble count — ignore trailing nibble gracefully
				f = f[:len(f)-1]
			}
			d, err := hex.DecodeString(f)
			if err != nil {
				continue
			}
			out = append(out, d...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no hex bytes recovered from input")
	}
	return out, nil
}

func looksLikeOffset(s string) bool {
	s = strings.TrimSuffix(s, ":")
	if len(s) < 4 {
		return false
	}
	return isHexRun(s)
}

func isHexRun(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hexPreview(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}

// hexDumpBlock returns a classic offset | hex | ascii dump for display.
func hexDumpBlock(b []byte, maxBytes int) string {
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "  %04x  ", off)
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&sb, "%02x ", b[i])
			} else {
				sb.WriteString("   ")
			}
			if i-off == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" ")
		for i := off; i < end; i++ {
			c := b[i]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ============================================================================
//  MAC address utilities
// ============================================================================

func macStr(b []byte) string {
	if len(b) < 6 {
		return "00:00:00:00:00:00"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func parseMAC(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", ":")
	parts := strings.Split(s, ":")
	if len(parts) == 1 && len(s) == 12 {
		// bare 12-nibble form
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 6 {
			return nil, errors.New("invalid MAC")
		}
		return b, nil
	}
	if len(parts) != 6 {
		return nil, errors.New("invalid MAC format")
	}
	out := make([]byte, 6)
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// macIsBroadcast reports an all-FF address.
func macIsBroadcast(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	for _, c := range b[:6] {
		if c != 0xff {
			return false
		}
	}
	return true
}

func macIsMulticast(b []byte) bool {
	return len(b) >= 1 && b[0]&0x01 == 0x01
}

// macIsLocallyAdministered detects the U/L bit → randomized / software MAC.
func macIsLocallyAdministered(b []byte) bool {
	return len(b) >= 1 && b[0]&0x02 == 0x02
}

// macRandomizationClass classifies a MAC's address type.
func macRandomizationClass(b []byte) string {
	if len(b) < 6 {
		return "invalid"
	}
	if macIsBroadcast(b) {
		return "broadcast"
	}
	if macIsMulticast(b) {
		return "multicast"
	}
	if macIsLocallyAdministered(b) {
		// Second nibble 2,6,A,E indicate randomized device identifiers.
		switch b[0] & 0x0f {
		case 0x02, 0x06, 0x0a, 0x0e:
			return "randomized"
		}
		return "locally-administered"
	}
	return "global-OUI"
}

func ouiKey(b []byte) string {
	if len(b) < 3 {
		return "000000"
	}
	return fmt.Sprintf("%02X%02X%02X", b[0], b[1], b[2])
}

// lookupVendor resolves the OUI (first 3 bytes) to a vendor name.
func lookupVendor(b []byte) string {
	if len(b) < 3 {
		return "Unknown"
	}
	if macIsBroadcast(b) {
		return "Broadcast"
	}
	if macRandomizationClass(b) == "randomized" {
		return "Randomized/Private"
	}
	if v, ok := ouiDB[ouiKey(b)]; ok {
		return v
	}
	return "Unknown"
}

// ouiDB — curated IEEE OUI → vendor prefixes commonly seen in wireless gear.
var ouiDB = map[string]string{
	"000C43": "Ralink", "001018": "Broadcom", "00037F": "Atheros",
	"000D93": "Apple", "001451": "Apple", "0017F2": "Apple",
	"001B63": "Apple", "0021E9": "Apple", "002332": "Apple",
	"3C0754": "Apple", "A4C361": "Apple", "F0DBF8": "Apple",
	"DC2B2A": "Apple", "88665A": "Apple", "A85C2C": "Apple",
	"001A11": "Google", "3C5AB4": "Google", "F4F5E8": "Google",
	"DA A1 19": "Google", "D4F547": "Google", "001FF3": "Apple",
	"F8E079": "Samsung", "5C0A5B": "Samsung", "B479A7": "Samsung",
	"0012FB": "Samsung", "002567": "Samsung", "386077": "Samsung",
	"001D0F": "TP-Link", "14CC20": "TP-Link", "50C7BF": "TP-Link",
	"A42BB0": "TP-Link", "C46E1F": "TP-Link", "EC086B": "TP-Link",
	"001A2B": "Cisco", "00400B": "Cisco", "0024C4": "Cisco",
	"58971E": "Cisco", "6400F1": "Cisco", "00059A": "Cisco",
	"0018F3": "ASUSTek", "001BFC": "ASUSTek", "2C56DC": "ASUSTek",
	"50465D": "ASUSTek", "AC220B": "ASUSTek", "D850E6": "ASUSTek",
	"001195": "D-Link", "00265A": "D-Link", "1CBDB9": "D-Link",
	"002401": "D-Link", "C8BE19": "D-Link", "B8A386": "D-Link",
	"000FB5": "Netgear", "00223F": "Netgear", "100D7F": "Netgear",
	"20E52A": "Netgear", "A040A0": "Netgear", "9C3DCF": "Netgear",
	"001601": "Buffalo", "00247E": "Ubiquiti", "0418D6": "Ubiquiti",
	"24A43C": "Ubiquiti", "68D79A": "Ubiquiti", "802AA8": "Ubiquiti",
	"FCECDA": "Ubiquiti", "74ACB9": "Ubiquiti", "B4FBE4": "Ubiquiti",
	"001346": "DLink", "0090A9": "Western Digital", "001C10": "Cisco-Linksys",
	"002369": "Cisco-Linksys", "C0C1C0": "Cisco-Linksys", "48F8B3": "Cisco-Linksys",
	"000625": "Linksys", "001217": "Cisco-Linksys", "0020A6": "Proxim",
	"001CDF": "Belkin", "08863B": "Belkin", "94103E": "Belkin",
	"B4750E": "Belkin", "001501": "Zyxel", "5C6A80": "Zyxel",
	"0013492": "Zyxel", "001349": "Zyxel", "FC3497": "Zyxel",
	"000393": "Apple", "0003AA": "Watlow", "009069": "Juniper",
	"2C6BF5": "Juniper", "3CE5A6": "Hangzhou", "0018E7": "Cameo",
	"001E58": "WistronNe", "001CF0": "D-Link", "001E2A": "Netgear",
	"00037A": "Taiyo", "001E8C": "ASUSTek", "0024B2": "Netgear",
	"0026F2": "Netgear", "E0469A": "Netgear", "C03F0E": "Netgear",
	"00904C": "Epigram", "ACF7F3": "Xiaomi", "286C07": "Xiaomi",
	"640980": "Xiaomi", "F8A45F": "Xiaomi", "742344": "Xiaomi",
	"4CB16C": "Huawei", "002568": "Huawei", "48435A": "Huawei",
	"5CA86A": "Huawei", "80B686": "Huawei", "E8CD2D": "Huawei",
	"001986": "Intel", "001F3B": "Intel", "0024D7": "Intel",
	"7C7A91": "Intel", "A0A8CD": "Intel", "E4A471": "Intel",
	"34E6D7": "Intel", "9CB6D0": "Intel", "5CE0C5": "Intel",
	"001DE1": "Intel", "00037B": "Dlink", "001B2F": "Netgear",
	"002275": "Belkin", "08BD43": "Netgear", "0C8268": "TP-Link",
	"3872C0": "CloudNet", "00156D": "Ubiquiti", "DC9FDB": "Ubiquiti",
	"44D9E7": "Ubiquiti", "788A20": "Ubiquiti", "F09FC2": "Ubiquiti",
	"0CB2B7": "Sonos", "5CAAFD": "Sonos", "949F3E": "Sonos",
	"B8E937": "Sonos", "347E5C": "Sonos", "F0F6C1": "Sonos",
	"001124": "Apple", "002608": "Apple", "0026BB": "Apple",
	"28CFE9": "Apple", "7CD1C3": "Apple", "9027E4": "Apple",
	"C82A14": "Apple", "E0ACCB": "Apple", "F0989D": "Apple",
	"40B395": "Apple", "6C4008": "Apple", "8866A5": "Apple",
}

// ============================================================================
//  CSV + file helpers
// ============================================================================

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func readFileBytes(path string) ([]byte, error) { return os.ReadFile(path) }

func readCSVRecords(path string) ([][]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	return r.ReadAll()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func atoiSafe(s string) int {
	s = strings.TrimSpace(s)
	v, _ := strconv.Atoi(s)
	return v
}

func atofSafe(s string) float64 {
	s = strings.TrimSpace(s)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ============================================================================
//  PCAP / PCAPNG reader (classic libpcap + minimal pcapng EPB)
// ============================================================================

// Link-layer header types we care about.
const (
	DLT_NULL        = 0
	DLT_EN10MB      = 1
	DLT_IEEE802_11  = 105
	DLT_RADIOTAP    = 127
	DLT_PPI         = 192
	DLT_BLUETOOTH   = 201 // BLUETOOTH_HCI_H4_WITH_PHDR
	DLT_BLE_LL      = 251 // BLUETOOTH_LE_LL
	DLT_IEEE802154  = 195 // IEEE802_15_4_WITHFCS
	DLT_IEEE802154B = 230 // IEEE802_15_4_NOFCS
	DLT_NORDIC_BLE  = 272
)

type capPacket struct {
	TsSec    uint32
	TsUsec   uint32
	OrigLen  uint32
	Data     []byte
	LinkType int
	Index    int
}

func (p capPacket) Time() time.Time {
	return time.Unix(int64(p.TsSec), int64(p.TsUsec)*1000).UTC()
}

type capFile struct {
	LinkType int
	Packets  []capPacket
	Format   string
}

// loadCapture auto-detects pcap, pcapng or raw-hex and returns parsed packets.
func loadCapture(path string) (*capFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCaptureBytes(b)
}

func parseCaptureBytes(b []byte) (*capFile, error) {
	if len(b) < 4 {
		return nil, errors.New("file too small")
	}
	magic := binary.BigEndian.Uint32(b[:4])
	switch magic {
	case 0x0a0d0d0a:
		return parsePcapng(b)
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		return parsePcap(b)
	}
	return nil, errors.New("unrecognized capture magic (not pcap/pcapng)")
}

func parsePcap(b []byte) (*capFile, error) {
	if len(b) < 24 {
		return nil, errors.New("short pcap global header")
	}
	magic := binary.BigEndian.Uint32(b[:4])
	var le bool
	var nano bool
	switch magic {
	case 0xa1b2c3d4:
		le = false
	case 0xd4c3b2a1:
		le = true
	case 0xa1b23c4d:
		le = false
		nano = true
	case 0x4d3cb2a1:
		le = true
		nano = true
	default:
		return nil, errors.New("bad pcap magic")
	}
	_ = nano
	ord := binary.ByteOrder(binary.BigEndian)
	if le {
		ord = binary.LittleEndian
	}
	linktype := int(ord.Uint32(b[20:24]))
	cf := &capFile{LinkType: linktype, Format: "pcap"}
	pos := 24
	idx := 0
	for pos+16 <= len(b) {
		tsSec := ord.Uint32(b[pos : pos+4])
		tsUsec := ord.Uint32(b[pos+4 : pos+8])
		caplen := ord.Uint32(b[pos+8 : pos+12])
		origlen := ord.Uint32(b[pos+12 : pos+16])
		pos += 16
		if caplen > 262144 || pos+int(caplen) > len(b) {
			break
		}
		data := make([]byte, caplen)
		copy(data, b[pos:pos+int(caplen)])
		pos += int(caplen)
		cf.Packets = append(cf.Packets, capPacket{
			TsSec: tsSec, TsUsec: tsUsec, OrigLen: origlen,
			Data: data, LinkType: linktype, Index: idx,
		})
		idx++
	}
	return cf, nil
}

func parsePcapng(b []byte) (*capFile, error) {
	cf := &capFile{Format: "pcapng"}
	pos := 0
	le := true
	linktype := DLT_EN10MB
	for pos+12 <= len(b) {
		btype := binary.LittleEndian.Uint32(b[pos : pos+4])
		blen := binary.LittleEndian.Uint32(b[pos+4 : pos+8])
		if btype == 0x0a0d0d0a {
			// SHB sets byte order via BOM
			if pos+12 <= len(b) {
				bom := binary.LittleEndian.Uint32(b[pos+8 : pos+12])
				le = bom == 0x1a2b3c4d
			}
		}
		if blen < 12 || pos+int(blen) > len(b) {
			break
		}
		ord := binary.ByteOrder(binary.LittleEndian)
		if !le {
			ord = binary.BigEndian
		}
		switch btype {
		case 0x00000001: // Interface Description Block
			if pos+10 <= len(b) {
				linktype = int(ord.Uint16(b[pos+8 : pos+10]))
				cf.LinkType = linktype
			}
		case 0x00000006: // Enhanced Packet Block
			if pos+28 <= len(b) {
				caplen := int(ord.Uint32(b[pos+20 : pos+24]))
				origlen := ord.Uint32(b[pos+24 : pos+28])
				dstart := pos + 28
				if caplen >= 0 && dstart+caplen <= len(b) && caplen < 262144 {
					data := make([]byte, caplen)
					copy(data, b[dstart:dstart+caplen])
					cf.Packets = append(cf.Packets, capPacket{
						OrigLen: origlen, Data: data,
						LinkType: linktype, Index: len(cf.Packets),
					})
				}
			}
		case 0x00000003: // Simple Packet Block
			if pos+12 <= len(b) {
				origlen := ord.Uint32(b[pos+8 : pos+12])
				dstart := pos + 12
				caplen := int(blen) - 16
				if caplen > 0 && dstart+caplen <= len(b) {
					data := make([]byte, caplen)
					copy(data, b[dstart:dstart+caplen])
					cf.Packets = append(cf.Packets, capPacket{
						OrigLen: origlen, Data: data,
						LinkType: linktype, Index: len(cf.Packets),
					})
				}
			}
		}
		pos += int(blen)
	}
	return cf, nil
}

// ============================================================================
//  Radiotap header parser (subset of the common present fields)
// ============================================================================

type radiotapInfo struct {
	Present    bool
	Length     int
	TSFT       uint64
	Flags      uint8
	Rate       float64 // Mbps
	ChannelMHz uint16
	ChanFlags  uint16
	SignalDBm  int8
	NoiseDBm   int8
	Antenna    uint8
	HasSignal  bool
	HasRate    bool
	HasChannel bool
	MCS        uint8
	HasMCS     bool
	BadFCS     bool
}

// present bit indices
const (
	rtTSFT      = 0
	rtFlags     = 1
	rtRate      = 2
	rtChannel   = 3
	rtFHSS      = 4
	rtDBmSignal = 5
	rtDBmNoise  = 6
	rtLockQual  = 7
	rtTxAtten   = 8
	rtDbTxAtten = 9
	rtDBmTxPow  = 10
	rtAntenna   = 11
	rtDBAnt     = 12
	rtDBAntNo   = 13
	rtMCS       = 19
)

func parseRadiotap(b []byte) (radiotapInfo, []byte) {
	var ri radiotapInfo
	if len(b) < 8 {
		return ri, b
	}
	// it_version(1) it_pad(1) it_len(2) it_present(4...)
	length := int(binary.LittleEndian.Uint16(b[2:4]))
	if length < 8 || length > len(b) {
		return ri, b
	}
	ri.Present = true
	ri.Length = length
	// collect present words (extended bit 31)
	var presents []uint32
	off := 4
	for {
		if off+4 > len(b) {
			break
		}
		p := binary.LittleEndian.Uint32(b[off : off+4])
		presents = append(presents, p)
		off += 4
		if p&(1<<31) == 0 {
			break
		}
	}
	r := newReader(b[:length], true)
	r.pos = off
	has := func(word, bit int) bool {
		if word >= len(presents) {
			return false
		}
		return presents[word]&(1<<uint(bit)) != 0
	}
	// Only parse first present word's common fields in order.
	if has(0, rtTSFT) {
		r.align(8)
		ri.TSFT, _ = r.u64()
	}
	if has(0, rtFlags) {
		v, _ := r.u8()
		ri.Flags = v
		if v&0x40 != 0 {
			ri.BadFCS = true
		}
	}
	if has(0, rtRate) {
		v, _ := r.u8()
		ri.Rate = float64(v) / 2.0
		ri.HasRate = true
	}
	if has(0, rtChannel) {
		r.align(2)
		f, _ := r.u16()
		fl, _ := r.u16()
		ri.ChannelMHz = f
		ri.ChanFlags = fl
		ri.HasChannel = true
	}
	if has(0, rtFHSS) {
		r.skip(2)
	}
	if has(0, rtDBmSignal) {
		v, _ := r.u8()
		ri.SignalDBm = int8(v)
		ri.HasSignal = true
	}
	if has(0, rtDBmNoise) {
		v, _ := r.u8()
		ri.NoiseDBm = int8(v)
	}
	if has(0, rtLockQual) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtTxAtten) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtDbTxAtten) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtDBmTxPow) {
		r.skip(1)
	}
	if has(0, rtAntenna) {
		v, _ := r.u8()
		ri.Antenna = v
	}
	if has(0, rtMCS) {
		if known, ok := r.u8(); ok {
			_ = known
			r.skip(1)
			if mcs, ok2 := r.u8(); ok2 {
				ri.MCS = mcs
				ri.HasMCS = true
			}
		}
	}
	// payload is everything after the radiotap header
	if length <= len(b) {
		return ri, b[length:]
	}
	return ri, b
}

// ============================================================================
//  IEEE 802.11 MAC header dissector
// ============================================================================

const (
	TypeMgmt = 0
	TypeCtrl = 1
	TypeData = 2
)

// management subtypes
const (
	MgmtAssocReq    = 0
	MgmtAssocResp   = 1
	MgmtReassocReq  = 2
	MgmtReassocResp = 3
	MgmtProbeReq    = 4
	MgmtProbeResp   = 5
	MgmtBeacon      = 8
	MgmtATIM        = 9
	MgmtDisassoc    = 10
	MgmtAuth        = 11
	MgmtDeauth      = 12
	MgmtAction      = 13
)

type dot11Frame struct {
	Version   int
	Type      int
	Subtype   int
	ToDS      bool
	FromDS    bool
	MoreFrag  bool
	Retry     bool
	PwrMgmt   bool
	MoreData  bool
	Protected bool
	Order     bool
	Duration  uint16
	Addr1     []byte // RA / DA
	Addr2     []byte // TA / SA
	Addr3     []byte // BSSID / DA / SA
	Addr4     []byte
	SeqNum    int
	FragNum   int
	QoS       uint16
	HasQoS    bool
	Body      []byte // frame body after fixed header (mgmt: starts at fixed params)
	FCSValid  bool
	Raw       []byte
}

func parseDot11(b []byte) (*dot11Frame, error) {
	if len(b) < 10 {
		return nil, errors.New("frame too short for 802.11 header")
	}
	f := &dot11Frame{Raw: b}
	fc := binary.LittleEndian.Uint16(b[0:2])
	f.Version = int(fc & 0x3)
	f.Type = int((fc >> 2) & 0x3)
	f.Subtype = int((fc >> 4) & 0xf)
	f.ToDS = fc&0x0100 != 0
	f.FromDS = fc&0x0200 != 0
	f.MoreFrag = fc&0x0400 != 0
	f.Retry = fc&0x0800 != 0
	f.PwrMgmt = fc&0x1000 != 0
	f.MoreData = fc&0x2000 != 0
	f.Protected = fc&0x4000 != 0
	f.Order = fc&0x8000 != 0
	f.Duration = binary.LittleEndian.Uint16(b[2:4])
	// addr1 always present
	if len(b) >= 10 {
		f.Addr1 = b[4:10]
	}
	off := 10
	if f.Type == TypeCtrl {
		// control frames: variable; only addr1 (and maybe addr2) present
		if len(b) >= 16 {
			f.Addr2 = b[10:16]
		}
		return f, nil
	}
	if len(b) >= 16 {
		f.Addr2 = b[10:16]
		off = 16
	}
	if len(b) >= 22 {
		f.Addr3 = b[16:22]
		off = 22
	}
	if len(b) >= 24 {
		sc := binary.LittleEndian.Uint16(b[22:24])
		f.FragNum = int(sc & 0xf)
		f.SeqNum = int(sc >> 4)
		off = 24
	}
	// 4-address data frame
	if f.Type == TypeData && f.ToDS && f.FromDS {
		if len(b) >= 30 {
			f.Addr4 = b[24:30]
			off = 30
		}
	}
	// QoS data
	if f.Type == TypeData && (f.Subtype&0x08) != 0 {
		if len(b) >= off+2 {
			f.QoS = binary.LittleEndian.Uint16(b[off : off+2])
			f.HasQoS = true
			off += 2
		}
	}
	if off <= len(b) {
		f.Body = b[off:]
	}
	return f, nil
}

func (f *dot11Frame) typeName() string {
	switch f.Type {
	case TypeMgmt:
		return "Management"
	case TypeCtrl:
		return "Control"
	case TypeData:
		return "Data"
	}
	return "Reserved"
}

func (f *dot11Frame) subtypeName() string {
	if f.Type == TypeMgmt {
		switch f.Subtype {
		case MgmtAssocReq:
			return "Assoc Request"
		case MgmtAssocResp:
			return "Assoc Response"
		case MgmtReassocReq:
			return "Reassoc Request"
		case MgmtReassocResp:
			return "Reassoc Response"
		case MgmtProbeReq:
			return "Probe Request"
		case MgmtProbeResp:
			return "Probe Response"
		case MgmtBeacon:
			return "Beacon"
		case MgmtATIM:
			return "ATIM"
		case MgmtDisassoc:
			return "Disassociation"
		case MgmtAuth:
			return "Authentication"
		case MgmtDeauth:
			return "Deauthentication"
		case MgmtAction:
			return "Action"
		}
	}
	if f.Type == TypeData {
		if f.Subtype == 0 {
			return "Data"
		}
		if f.Subtype == 4 {
			return "Null"
		}
		if f.Subtype&0x08 != 0 {
			return "QoS Data"
		}
	}
	if f.Type == TypeCtrl {
		switch f.Subtype {
		case 8:
			return "Block Ack Req"
		case 9:
			return "Block Ack"
		case 11:
			return "RTS"
		case 12:
			return "CTS"
		case 13:
			return "ACK"
		}
	}
	return fmt.Sprintf("Subtype-%d", f.Subtype)
}

// bssid returns the best-effort BSSID depending on DS bits.
func (f *dot11Frame) bssid() []byte {
	switch {
	case f.Type == TypeMgmt:
		return f.Addr3
	case !f.ToDS && !f.FromDS:
		return f.Addr3
	case f.ToDS && !f.FromDS:
		return f.Addr1
	case !f.ToDS && f.FromDS:
		return f.Addr2
	default:
		return f.Addr3
	}
}

// ============================================================================
//  Information Element (tagged parameter) parsing
// ============================================================================

type infoElement struct {
	ID   int
	Len  int
	Data []byte
}

const (
	eidSSID      = 0
	eidRates     = 1
	eidDSParam   = 3
	eidTIM       = 5
	eidCountry   = 7
	eidERP       = 42
	eidHTCap     = 45
	eidRSN       = 48
	eidExtRates  = 50
	eidHTInfo    = 61
	eidRMEnabled = 70
	eidExtCap    = 127
	eidVHTCap    = 191
	eidVHTOp     = 192
	eidVendor    = 221
	eidExtension = 255
)

// parseIEs reads tag/len/value triples from a management-frame body offset.
func parseIEs(body []byte) []infoElement {
	var ies []infoElement
	pos := 0
	for pos+2 <= len(body) {
		id := int(body[pos])
		l := int(body[pos+1])
		pos += 2
		if pos+l > len(body) {
			break
		}
		data := body[pos : pos+l]
		ies = append(ies, infoElement{ID: id, Len: l, Data: data})
		pos += l
	}
	return ies
}

func findIE(ies []infoElement, id int) *infoElement {
	for i := range ies {
		if ies[i].ID == id {
			return &ies[i]
		}
	}
	return nil
}

func ieSSID(ies []infoElement) string {
	ie := findIE(ies, eidSSID)
	if ie == nil {
		return ""
	}
	if ie.Len == 0 {
		return "<hidden>"
	}
	s := string(ie.Data)
	// hidden SSIDs can be all-zero
	allZero := true
	for _, c := range ie.Data {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "<hidden>"
	}
	return sanitizeSSID(s)
}

func sanitizeSSID(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			sb.WriteRune(r)
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}
	return sb.String()
}

func ieChannel(ies []infoElement) int {
	if ie := findIE(ies, eidDSParam); ie != nil && ie.Len >= 1 {
		return int(ie.Data[0])
	}
	if ie := findIE(ies, eidHTInfo); ie != nil && ie.Len >= 1 {
		return int(ie.Data[0])
	}
	return 0
}

func ieSupportedRates(ies []infoElement) []float64 {
	var rates []float64
	for _, id := range []int{eidRates, eidExtRates} {
		if ie := findIE(ies, id); ie != nil {
			for _, r := range ie.Data {
				rates = append(rates, float64(r&0x7f)/2.0)
			}
		}
	}
	return rates
}

// ============================================================================
//  RSN / WPA security parsing
// ============================================================================

type rsnInfo struct {
	Present     bool
	WPA1        bool
	WPA2        bool
	WPA3        bool
	GroupCipher string
	Pairwise    []string
	AKM         []string
	MFPCapable  bool
	MFPRequired bool
	PMKIDs      [][]byte
}

func cipherName(suite [4]byte) string {
	// OUI 00-0F-AC (RSN) / 00-50-F2 (WPA)
	t := suite[3]
	switch t {
	case 0:
		return "Use-Group"
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP-128"
	case 5:
		return "WEP-104"
	case 6:
		return "BIP-CMAC-128"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	}
	return fmt.Sprintf("cipher-%d", t)
}

func akmName(suite [4]byte) string {
	t := suite[3]
	switch t {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE"
	case 9:
		return "FT-SAE"
	case 11:
		return "802.1X-SuiteB"
	case 12:
		return "802.1X-SuiteB-192"
	case 18:
		return "OWE"
	}
	return fmt.Sprintf("akm-%d", t)
}

func parseRSN(ie *infoElement) rsnInfo {
	var ri rsnInfo
	if ie == nil || ie.Len < 2 {
		return ri
	}
	ri.Present = true
	ri.WPA2 = true
	d := ie.Data
	pos := 2 // version
	readSuite := func() ([4]byte, bool) {
		var s [4]byte
		if pos+4 > len(d) {
			return s, false
		}
		copy(s[:], d[pos:pos+4])
		pos += 4
		return s, true
	}
	if g, ok := readSuite(); ok {
		ri.GroupCipher = cipherName(g)
	}
	if pos+2 <= len(d) {
		n := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2
		for i := 0; i < n; i++ {
			if s, ok := readSuite(); ok {
				ri.Pairwise = append(ri.Pairwise, cipherName(s))
			}
		}
	}
	if pos+2 <= len(d) {
		n := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2
		for i := 0; i < n; i++ {
			if s, ok := readSuite(); ok {
				name := akmName(s)
				ri.AKM = append(ri.AKM, name)
				if name == "SAE" || name == "FT-SAE" {
					ri.WPA3 = true
				}
			}
		}
	}
	if pos+2 <= len(d) {
		caps := binary.LittleEndian.Uint16(d[pos : pos+2])
		pos += 2
		ri.MFPRequired = caps&0x0040 != 0
		ri.MFPCapable = caps&0x0080 != 0
		// PMKID count + list
		if pos+2 <= len(d) {
			pc := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
			pos += 2
			for i := 0; i < pc; i++ {
				if pos+16 <= len(d) {
					id := make([]byte, 16)
					copy(id, d[pos:pos+16])
					ri.PMKIDs = append(ri.PMKIDs, id)
					pos += 16
				}
			}
		}
	}
	return ri
}

// parseWPA1 handles the Microsoft WPA vendor IE (221, OUI 00-50-F2 type 1).
func parseWPA1(ies []infoElement) bool {
	for _, ie := range ies {
		if ie.ID == eidVendor && ie.Len >= 4 {
			if ie.Data[0] == 0x00 && ie.Data[1] == 0x50 && ie.Data[2] == 0xf2 && ie.Data[3] == 0x01 {
				return true
			}
		}
	}
	return false
}

// securityString summarises the privacy posture of a BSS.
func securityString(privacy bool, rsn rsnInfo, wpa1 bool) string {
	if rsn.WPA3 {
		if contains(rsn.AKM, "OWE") {
			return "OWE"
		}
		return "WPA3-SAE"
	}
	if rsn.Present {
		if contains(rsn.AKM, "802.1X") || contains(rsn.AKM, "802.1X-SHA256") {
			return "WPA2-Enterprise"
		}
		return "WPA2-PSK"
	}
	if wpa1 {
		return "WPA-TKIP"
	}
	if privacy {
		return "WEP"
	}
	return "OPEN"
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// ============================================================================
//  Channel / frequency maps (2.4 / 5 / 6 GHz)
// ============================================================================

func freqToChannel(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5
	case mhz >= 5160 && mhz <= 5885:
		return (mhz - 5000) / 5
	case mhz >= 5955 && mhz <= 7115: // 6 GHz
		return (mhz - 5950) / 5
	}
	return 0
}

func channelToFreq(ch int) int {
	switch {
	case ch == 14:
		return 2484
	case ch >= 1 && ch <= 13:
		return 2407 + ch*5
	case ch >= 32 && ch <= 177:
		return 5000 + ch*5
	}
	return 0
}

func bandForChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4GHz"
	case ch >= 32 && ch <= 177:
		return "5GHz"
	case ch >= 1 && ch <= 233:
		return "6GHz"
	}
	return "?"
}

func bandForFreq(mhz int) string {
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4GHz"
	case mhz >= 4900 && mhz < 5900:
		return "5GHz"
	case mhz >= 5925 && mhz <= 7125:
		return "6GHz"
	}
	return "?"
}

// is24NonOverlap reports whether a 2.4GHz channel is one of 1/6/11.
func is24NonOverlap(ch int) bool { return ch == 1 || ch == 6 || ch == 11 }

// dfsChannel reports whether a 5GHz channel requires DFS.
func dfsChannel(ch int) bool {
	return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144)
}

// signalQuality maps dBm to a 0..100 quality and label.
func signalQuality(dbm int) (int, string) {
	q := 2 * (dbm + 100)
	q = clampInt(q, 0, 100)
	label := "Unusable"
	switch {
	case dbm >= -50:
		label = "Excellent"
	case dbm >= -60:
		label = "Good"
	case dbm >= -70:
		label = "Fair"
	case dbm >= -80:
		label = "Weak"
	}
	return q, label
}

// ============================================================================
//  EAPOL / 802.1X key-frame parser
// ============================================================================

type eapolKey struct {
	Valid       bool
	Version     int
	Type        int
	KeyDescType int
	KeyInfo     uint16
	KeyLength   int
	ReplayCtr   uint64
	Nonce       []byte
	KeyIV       []byte
	KeyRSC      []byte
	MIC         []byte
	KeyDataLen  int
	KeyData     []byte
	MsgNum      int // 1..4 within 4-way handshake
	Pairwise    bool
	Install     bool
	ACK         bool
	MICSet      bool
	Secure      bool
	HasPMKID    bool
	PMKID       []byte
}

// parseEAPOL parses an EAPOL frame body (after the LLC/SNAP, starting at the
// EAPOL version byte). micLen chosen by key descriptor.
func parseEAPOL(b []byte) eapolKey {
	var k eapolKey
	if len(b) < 4 {
		return k
	}
	k.Version = int(b[0])
	k.Type = int(b[1])
	plen := int(binary.BigEndian.Uint16(b[2:4]))
	if k.Type != 3 { // 3 = EAPOL-Key
		return k
	}
	body := b[4:]
	if plen <= len(body) {
		body = body[:plen]
	}
	if len(body) < 95 {
		return k
	}
	k.Valid = true
	k.KeyDescType = int(body[0])
	k.KeyInfo = binary.BigEndian.Uint16(body[1:3])
	k.KeyLength = int(binary.BigEndian.Uint16(body[3:5]))
	k.ReplayCtr = binary.BigEndian.Uint64(body[5:13])
	k.Nonce = append([]byte(nil), body[13:45]...)
	k.KeyIV = append([]byte(nil), body[45:61]...)
	k.KeyRSC = append([]byte(nil), body[61:69]...)
	// 69:77 reserved
	k.MIC = append([]byte(nil), body[77:93]...)
	k.KeyDataLen = int(binary.BigEndian.Uint16(body[93:95]))
	if 95+k.KeyDataLen <= len(body) {
		k.KeyData = append([]byte(nil), body[95:95+k.KeyDataLen]...)
	}
	ki := k.KeyInfo
	k.Pairwise = ki&0x0008 != 0
	k.Install = ki&0x0040 != 0
	k.ACK = ki&0x0080 != 0
	k.MICSet = ki&0x0100 != 0
	k.Secure = ki&0x0200 != 0
	// classify message number of 4-way handshake
	switch {
	case k.ACK && !k.MICSet && !k.Install:
		k.MsgNum = 1
	case !k.ACK && k.MICSet && !k.Secure && !k.Install:
		k.MsgNum = 2
	case k.ACK && k.MICSet && k.Install:
		k.MsgNum = 3
	case !k.ACK && k.MICSet && k.Secure && !k.Install:
		k.MsgNum = 4
	}
	// scan key data for PMKID KDE (00-0F-AC type 4)
	k.PMKID, k.HasPMKID = extractPMKID(k.KeyData)
	return k
}

func extractPMKID(kd []byte) ([]byte, bool) {
	pos := 0
	for pos+2 <= len(kd) {
		if kd[pos] != 0xdd {
			// not a KDE; bail (RSN KDE uses 0xdd type)
			break
		}
		l := int(kd[pos+1])
		if pos+2+l > len(kd) {
			break
		}
		kde := kd[pos+2 : pos+2+l]
		if len(kde) >= 4 && kde[0] == 0x00 && kde[1] == 0x0f && kde[2] == 0xac && kde[3] == 0x04 {
			if len(kde) >= 20 {
				return append([]byte(nil), kde[4:20]...), true
			}
		}
		pos += 2 + l
	}
	return nil, false
}

// findEAPOLInPayload locates an EAPOL payload within a data frame body by
// scanning for the 888E ethertype after LLC/SNAP (AA AA 03 00 00 00 88 8E).
func findEAPOLInPayload(body []byte) []byte {
	snap := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e}
	if idx := bytes.Index(body, snap); idx >= 0 {
		return body[idx+8:]
	}
	// try raw 888E
	e := []byte{0x88, 0x8e}
	if idx := bytes.Index(body, e); idx >= 0 && idx+2 < len(body) {
		return body[idx+2:]
	}
	return nil
}

// ============================================================================
//  Findings + Report model and 5-format export engine
// ============================================================================

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Entity      string   `json:"entity"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
	MITRE       []string `json:"mitre,omitempty"`
}

type Report struct {
	Tool      string            `json:"tool"`
	Version   string            `json:"version"`
	Target    string            `json:"target"`
	Generated string            `json:"generated"`
	Grade     string            `json:"grade"`
	Score     float64           `json:"score"`
	Summary   map[string]string `json:"summary"`
	Findings  []Finding         `json:"findings"`
	TextBody  string            `json:"-"`
}

func newReport(target string) *Report {
	return &Report{
		Tool:      APPNAME,
		Version:   VERSION,
		Target:    target,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Summary:   map[string]string{},
	}
}

func (rep *Report) add(f Finding) {
	if f.Severity == "" {
		f.Severity = scoreToSeverity(f.Score)
	}
	rep.Findings = append(rep.Findings, f)
}

func (rep *Report) sortFindings() {
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		ri, rj := sevRank(rep.Findings[i].Severity), sevRank(rep.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return rep.Findings[i].Score > rep.Findings[j].Score
	})
}

func (rep *Report) countBySeverity() map[string]int {
	m := map[string]int{}
	for _, f := range rep.Findings {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}

// computeGrade derives a posture grade from finding severities.
func (rep *Report) computeGrade() {
	penalty := 0.0
	for _, f := range rep.Findings {
		switch strings.ToUpper(f.Severity) {
		case SevCritical:
			penalty += 22
		case SevHigh:
			penalty += 12
		case SevMedium:
			penalty += 6
		case SevLow:
			penalty += 2
		}
	}
	score := clamp(100-penalty, 0, 100)
	rep.Score = score
	rep.Grade = gradeFromScore(score)
}

func summaryKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ---------------------------------------------------------------------------
//  Export: TXT
// ---------------------------------------------------------------------------

func exportTXT(rep *Report) string {
	var sb strings.Builder
	w := 72
	sb.WriteString(hr(w) + "\n")
	sb.WriteString(fmt.Sprintf("%s  —  %s\n", APPNAME, TAGLINE))
	sb.WriteString("Author: khaled.s.haddad    Website: owlsec.org\n")
	sb.WriteString(hr(w) + "\n")
	sb.WriteString(fmt.Sprintf("Target     : %s\n", rep.Target))
	sb.WriteString(fmt.Sprintf("Generated  : %s\n", rep.Generated))
	sb.WriteString(fmt.Sprintf("Version    : %s\n", rep.Version))
	sb.WriteString(fmt.Sprintf("Posture    : %s  (score %.1f/100 — %s)\n", rep.Grade, rep.Score, gradeLabel(rep.Grade)))
	sb.WriteString(hr(w) + "\n\n")
	if len(rep.Summary) > 0 {
		sb.WriteString("SUMMARY\n")
		for _, k := range summaryKeys(rep.Summary) {
			sb.WriteString(fmt.Sprintf("  %-24s %s\n", k+":", rep.Summary[k]))
		}
		sb.WriteString("\n")
	}
	if rep.TextBody != "" {
		sb.WriteString(rep.TextBody)
		sb.WriteString("\n")
	}
	counts := rep.countBySeverity()
	sb.WriteString(fmt.Sprintf("FINDINGS (%d)  [C:%d H:%d M:%d L:%d I:%d]\n",
		len(rep.Findings), counts[SevCritical], counts[SevHigh],
		counts[SevMedium], counts[SevLow], counts[SevInfo]))
	sb.WriteString(hr(w) + "\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("[%d] (%s) %s\n", i+1, f.Severity, f.Title))
		if f.Entity != "" {
			sb.WriteString(fmt.Sprintf("    Entity : %s\n", f.Entity))
		}
		if f.Detail != "" {
			sb.WriteString(fmt.Sprintf("    Detail : %s\n", f.Detail))
		}
		if len(f.MITRE) > 0 {
			sb.WriteString(fmt.Sprintf("    MITRE  : %s\n", strings.Join(f.MITRE, ", ")))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("    Fix    : %s\n", f.Remediation))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(hr(w) + "\n")
	sb.WriteString("Authorized testing only. Generated by " + APPNAME + " v" + VERSION + ".\n")
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Export: Markdown
// ---------------------------------------------------------------------------

func exportMD(rep *Report) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s — Report\n\n", APPNAME))
	sb.WriteString(fmt.Sprintf("*%s*\n\n", TAGLINE))
	sb.WriteString(fmt.Sprintf("- **Target:** %s\n", rep.Target))
	sb.WriteString(fmt.Sprintf("- **Generated:** %s\n", rep.Generated))
	sb.WriteString(fmt.Sprintf("- **Version:** %s\n", rep.Version))
	sb.WriteString(fmt.Sprintf("- **Posture:** `%s` (score %.1f/100 — %s)\n\n", rep.Grade, rep.Score, gradeLabel(rep.Grade)))
	if len(rep.Summary) > 0 {
		sb.WriteString("## Summary\n\n")
		sb.WriteString("| Metric | Value |\n|---|---|\n")
		for _, k := range summaryKeys(rep.Summary) {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", k, rep.Summary[k]))
		}
		sb.WriteString("\n")
	}
	if rep.TextBody != "" {
		sb.WriteString("## Details\n\n```\n")
		sb.WriteString(rep.TextBody)
		sb.WriteString("\n```\n\n")
	}
	sb.WriteString(fmt.Sprintf("## Findings (%d)\n\n", len(rep.Findings)))
	sb.WriteString("| # | Severity | Title | Entity | MITRE |\n|---|---|---|---|---|\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
			i+1, f.Severity, mdEsc(f.Title), mdEsc(f.Entity), strings.Join(f.MITRE, " ")))
	}
	sb.WriteString("\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, f.Title, f.Severity))
		if f.Entity != "" {
			sb.WriteString(fmt.Sprintf("- **Entity:** %s\n", f.Entity))
		}
		if f.Detail != "" {
			sb.WriteString(fmt.Sprintf("- **Detail:** %s\n", f.Detail))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
		}
		if len(f.MITRE) > 0 {
			sb.WriteString(fmt.Sprintf("- **MITRE ATT&CK:** %s\n", strings.Join(f.MITRE, ", ")))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n---\n*Authorized testing only. " + APPNAME + " v" + VERSION + " — owlsec.org*\n")
	return sb.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ---------------------------------------------------------------------------
//  Export: JSON
// ---------------------------------------------------------------------------

func exportJSON(rep *Report) string {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ---------------------------------------------------------------------------
//  Export: CSV
// ---------------------------------------------------------------------------

func exportCSV(rep *Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"index", "severity", "score", "title", "entity", "detail", "mitre", "remediation"})
	for i, f := range rep.Findings {
		w.Write([]string{
			strconv.Itoa(i + 1),
			f.Severity,
			fmt.Sprintf("%.1f", f.Score),
			f.Title,
			f.Entity,
			f.Detail,
			strings.Join(f.MITRE, " "),
			f.Remediation,
		})
	}
	w.Flush()
	return buf.String()
}

// ---------------------------------------------------------------------------
//  Export: SARIF 2.1.0
// ---------------------------------------------------------------------------

func exportSARIF(rep *Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifProps struct {
		Severity string   `json:"severity,omitempty"`
		Score    float64  `json:"score,omitempty"`
		MITRE    []string `json:"mitre,omitempty"`
		Entity   string   `json:"entity,omitempty"`
	}
	type sarifRule struct {
		ID               string     `json:"id"`
		Name             string     `json:"name"`
		ShortDescription sarifMsg   `json:"shortDescription"`
		FullDescription  sarifMsg   `json:"fullDescription"`
		HelpURI          string     `json:"helpUri,omitempty"`
		Properties       sarifProps `json:"properties"`
	}
	type sarifArtifactLoc struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine"`
	}
	type sarifPhysLoc struct {
		ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
		Region           sarifRegion      `json:"region"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string     `json:"ruleId"`
		Level      string     `json:"level"`
		Message    sarifMsg   `json:"message"`
		Locations  []sarifLoc `json:"locations"`
		Properties sarifProps `json:"properties"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifToolBlock struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifToolBlock `json:"tool"`
		Results []sarifResult  `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	ruleIdx := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for i, f := range rep.Findings {
		rid := f.ID
		if rid == "" {
			rid = fmt.Sprintf("%s-RULE-%d", APPNAME, i+1)
		}
		if !ruleIdx[rid] {
			ruleIdx[rid] = true
			rules = append(rules, sarifRule{
				ID:               rid,
				Name:             f.Title,
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: f.Detail},
				HelpURI:          "https://owlsec.org",
				Properties:       sarifProps{Severity: f.Severity, Score: f.Score, MITRE: f.MITRE},
			})
		}
		entity := f.Entity
		if entity == "" {
			entity = rep.Target
		}
		results = append(results, sarifResult{
			RuleID:  rid,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: f.Detail},
			Locations: []sarifLoc{{PhysicalLocation: sarifPhysLoc{
				ArtifactLocation: sarifArtifactLoc{URI: entity},
				Region:           sarifRegion{StartLine: 1},
			}}},
			Properties: sarifProps{Severity: f.Severity, Score: f.Score, MITRE: f.MITRE, Entity: f.Entity},
		})
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifToolBlock{Driver: sarifDriver{
				Name:           APPNAME,
				Version:        VERSION,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// renderReport returns the report in the requested format.
func renderReport(rep *Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "txt", "text", "":
		return exportTXT(rep), nil
	case "md", "markdown":
		return exportMD(rep), nil
	case "json":
		return exportJSON(rep), nil
	case "csv":
		return exportCSV(rep), nil
	case "sarif":
		return exportSARIF(rep), nil
	}
	return "", fmt.Errorf("unknown format %q (use txt|md|json|csv|sarif)", format)
}

// writeReport emits to stdout or a file.
func writeReport(rep *Report, format, outPath string) error {
	out, err := renderReport(rep, format)
	if err != nil {
		return err
	}
	if outPath == "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := os.WriteFile(outPath, []byte(out), 0644); err != nil {
		return err
	}
	abs, _ := filepath.Abs(outPath)
	okMsg("Report written: " + abs + " (" + format + ")")
	return nil
}

// ============================================================================
//  HOW TO USE renderer (mandatory help view) + CLI plumbing
// ============================================================================

type howSection struct {
	Title string
	Lines []string
}

// renderHowto prints the full HOW TO USE screen.
func renderHowto(secs []howSection) {
	clear()
	banner()
	for _, s := range secs {
		sectionHeader(s.Title)
		for _, ln := range s.Lines {
			if strings.HasPrefix(ln, "#") {
				fmt.Println("  " + col(strings.TrimPrefix(ln, "#"), YLW+B))
			} else if strings.HasPrefix(ln, "- ") {
				bullet(strings.TrimPrefix(ln, "- "))
			} else if ln == "" {
				fmt.Println()
			} else {
				fmt.Println("  " + col(ln, W))
			}
		}
	}
	fmt.Println()
	line(64)
	fmt.Println("  " + col("Authorized testing only — written permission required.", CY+B))
}

// legalWarningLines is the standard LEGAL & ETHICAL WARNING block shared by all
// tools (each tool appends protocol-specific notes).
func legalWarningLines() []string {
	return []string{
		"This tool is for AUTHORIZED security testing and education ONLY.",
		"",
		"- Use ONLY on networks, devices and spectrum you own or have",
		"  EXPLICIT WRITTEN PERMISSION to assess.",
		"- Interception, jamming, deauthentication or spoofing of radio",
		"  networks without authorization is ILLEGAL in most jurisdictions",
		"  (e.g. CFAA, Computer Misuse Act, Wireless Telegraphy Act, RF",
		"  regulatory law) and may carry criminal penalties.",
		"- This build operates OFFLINE on capture/log files you supply; it",
		"  does not transmit, inject, or control any radio hardware.",
		"- You are solely responsible for lawful, ethical use. The author",
		"  (khaled.s.haddad) and owlsec.org accept NO liability for misuse.",
	}
}

func navigationLines(items []string) []string {
	out := []string{"Use the number keys shown in the main menu:"}
	out = append(out, "")
	for i, it := range items {
		out = append(out, fmt.Sprintf("- [%d] %s", i+1, it))
	}
	out = append(out, "- [H] Help & Usage (this screen)")
	out = append(out, "- [0] Exit the program")
	out = append(out, "")
	out = append(out, "Press Enter at any [↩] prompt to return to the menu.")
	return out
}

// ---------------------------------------------------------------------------
//  CLI helpers
// ---------------------------------------------------------------------------

func printVersion() {
	fmt.Printf("%s v%s\n", APPNAME, VERSION)
	fmt.Println("Author : khaled.s.haddad")
	fmt.Println("Website: owlsec.org")
	fmt.Println("Build  : Go stdlib, static (CGO disabled), OWL Batch 3 (Wireless)")
}

// severitySummaryLine renders a compact finding tally.
func severitySummaryLine(rep *Report) string {
	c := rep.countBySeverity()
	return fmt.Sprintf("Critical:%d High:%d Medium:%d Low:%d Info:%d",
		c[SevCritical], c[SevHigh], c[SevMedium], c[SevLow], c[SevInfo])
}

// printFindingsTable renders findings to the interactive TUI.
func printFindingsTable(rep *Report) {
	if len(rep.Findings) == 0 {
		info("No findings for this run.")
		return
	}
	rows := [][]string{}
	for i, f := range rep.Findings {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			f.Severity,
			truncStr(f.Title, 34),
			truncStr(f.Entity, 20),
			strings.Join(f.MITRE, " "),
		})
	}
	table([]string{"#", "SEVERITY", "FINDING", "ENTITY", "MITRE"}, rows)
}

// gradeBanner prints the posture grade with color.
func gradeBanner(rep *Report) {
	rep.computeGrade()
	g := rep.Grade
	fmt.Println()
	fmt.Println("  " + col(" POSTURE GRADE ", gradeColor(g)+"\033[7m") + "  " +
		col(g, gradeColor(g)) + col(fmt.Sprintf("   score %.1f/100 — %s", rep.Score, gradeLabel(g)), GY))
}

// writeOrShow writes the report (file or stdout) and reports status in the TUI.
func writeOrShow(rep *Report, format, out string) {
	if err := writeReport(rep, format, out); err != nil {
		errMsg(err.Error())
	}
}

// chooseFormat validates a format string.
func chooseFormat(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "txt", "md", "json", "csv", "sarif":
		return s
	}
	return "txt"
}

// parseIntList parses "1,2,3" or "1-11" style lists.
func parseIntList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			r := strings.SplitN(part, "-", 2)
			a := atoiSafe(r[0])
			b := atoiSafe(r[1])
			if a <= b {
				for i := a; i <= b; i++ {
					out = append(out, i)
				}
			}
		} else {
			out = append(out, atoiSafe(part))
		}
	}
	return out
}

// nowStamp is a filesystem-friendly timestamp.
func nowStamp() string { return time.Now().Format("20060102-150405") }

// defaultOutName builds an export filename when the user omits one.
func defaultOutName(kind, format string) string {
	ext := format
	if format == "md" {
		ext = "md"
	}
	return fmt.Sprintf("%s-%s-%s.%s", strings.ToLower(APPNAME), kind, nowStamp(), ext)
}

// ensure helpers are considered used even by lean tools.
var _ = errors.New
var _ = math.Sqrt
var _ = hex.EncodeToString
var _ = sort.Ints
var _ = filepath.Base
var _ = bufio.NewReader

// ============================================================================
//  Tool contract hooks + unified main/CLI/interactive engine
// ============================================================================

// Each tool wires these in its init(). The engine below is identical across the
// batch; the domain depth lives in each tool's hook implementations.
var (
	hookHowto         func() []howSection
	hookDemo          func() *Report
	hookAnalyze       func(path string) (*Report, error)
	hookActions       func() []menuAction
	hookRegisterFlags func(*flag.FlagSet)
	hookUsageExtra    func()
)

type menuAction struct {
	label string
	run   func()
}

// lastReport is the most recent analysis result, shared across menu actions.
var lastReport *Report

// common CLI flags
var (
	flagInput   string
	flagFormat  string
	flagOutput  string
	flagNoColor bool
)

func printUsage() {
	if !noColor {
		banner()
	} else {
		fmt.Printf("%s — %s\n", APPNAME, TAGLINE)
		fmt.Println("Author: khaled.s.haddad | owlsec.org")
	}
	fmt.Println()
	fmt.Println(col("USAGE", CY+B))
	fmt.Printf("  %s [flags]\n", strings.ToLower(APPNAME))
	fmt.Printf("  %s                 # launch interactive cyan TUI\n", strings.ToLower(APPNAME))
	fmt.Printf("  %s --input FILE    # analyze a capture/log and print a report\n", strings.ToLower(APPNAME))
	fmt.Printf("  %s --demo          # run a self-contained synthetic demo\n", strings.ToLower(APPNAME))
	fmt.Println()
	fmt.Println(col("CORE FLAGS", CY+B))
	fmt.Println("  -h, --help            Show this help")
	fmt.Println("      --version         Show version information")
	fmt.Println("      --howto           Show the HOW TO USE screen (legal, steps, nav)")
	fmt.Println("      --demo            Run a synthetic, self-contained demonstration")
	fmt.Println("      --input FILE      Input capture/log file (alias: --pcap)")
	fmt.Println("      --format FMT      Output format: txt|md|json|csv|sarif (default txt)")
	fmt.Println("      --output FILE     Write report to FILE instead of stdout")
	fmt.Println("      --no-color        Disable ANSI colors")
	fmt.Println("      --selftest        Run built-in self-tests and exit")
	if hookUsageExtra != nil {
		fmt.Println()
		fmt.Println(col("TOOL FLAGS", CY+B))
		hookUsageExtra()
	}
	fmt.Println()
	fmt.Println(col("EXAMPLES", CY+B))
	fmt.Println("  " + strings.ToLower(APPNAME) + " --input capture.pcap --format sarif --output ap.sarif")
	fmt.Println("  " + strings.ToLower(APPNAME) + " --input probes.pcapng --format md")
	fmt.Println("  " + strings.ToLower(APPNAME) + " --demo --format json")
	fmt.Println()
	fmt.Println(col("CATEGORY", CY+B) + "  " + CATEGORY)
	fmt.Println(col("MITRE   ", CY+B) + "  " + MITRE)
	fmt.Println()
	fmt.Println(col("Authorized testing only. No warranty. See --howto for legal terms.", DIM))
}

func main() {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var showHelp, showHelpS, showVer, showHowto, demo bool
	fs.BoolVar(&showHelp, "help", false, "show help")
	fs.BoolVar(&showHelpS, "h", false, "show help")
	fs.BoolVar(&showVer, "version", false, "show version")
	fs.BoolVar(&showHowto, "howto", false, "show HOW TO USE")
	fs.BoolVar(&demo, "demo", false, "run synthetic demo")
	fs.StringVar(&flagInput, "input", "", "input capture/log file")
	fs.StringVar(&flagInput, "pcap", "", "input capture file (alias of --input)")
	fs.StringVar(&flagFormat, "format", "txt", "txt|md|json|csv|sarif")
	fs.StringVar(&flagOutput, "output", "", "write report to file")
	fs.BoolVar(&flagNoColor, "no-color", false, "disable colors")
	var selftest bool
	fs.BoolVar(&selftest, "selftest", false, "run built-in self-tests and exit")
	if hookRegisterFlags != nil {
		hookRegisterFlags(fs)
	}
	fs.Usage = printUsage
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			printUsage()
			return
		}
		errMsg(err.Error())
		os.Exit(2)
	}
	if flagNoColor {
		noColor = true
	}
	flagFormat = chooseFormat(flagFormat)

	switch {
	case showHelp || showHelpS:
		printUsage()
		return
	case showVer:
		printVersion()
		return
	case selftest:
		os.Exit(runSelfTest())
	case showHowto:
		renderHowto(hookHowto())
		return
	case demo:
		rep := hookDemo()
		rep.computeGrade()
		rep.sortFindings()
		lastReport = rep
		if flagOutput == "" && flagFormat == "txt" {
			fmt.Println(col(APPNAME+" — synthetic demo run", CY+B))
		}
		writeOrShow(rep, flagFormat, flagOutput)
		return
	case flagInput != "":
		rep, err := hookAnalyze(flagInput)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		rep.computeGrade()
		rep.sortFindings()
		lastReport = rep
		writeOrShow(rep, flagFormat, flagOutput)
		return
	}

	// No actionable flags → interactive TUI.
	if len(os.Args) == 1 {
		standardInteractive()
		return
	}
	// Flags given but nothing to do.
	printUsage()
}

// standardInteractive drives the menu-based cyan TUI loop.
func standardInteractive() {
	for {
		acts := hookActions()
		labels := make([]string, 0, len(acts)+1)
		for _, a := range acts {
			labels = append(labels, a.label)
		}
		labels = append(labels, "HOW TO USE")
		sel := strings.TrimSpace(menu(TAGLINE, labels))
		if sel == "00" || sel == "0" || sel == "" || strings.EqualFold(sel, "q") || strings.EqualFold(sel, "exit") {
			clear()
			banner()
			okMsg("Session closed. Authorized testing only — stay ethical.")
			return
		}
		if strings.EqualFold(sel, "h") || strings.EqualFold(sel, "help") || sel == "?" {
			renderHowto(hookHowto())
			pause()
			continue
		}
		n, err := strconv.Atoi(sel)
		if err != nil {
			continue
		}
		if n >= 1 && n <= len(acts) {
			clear()
			banner()
			acts[n-1].run()
			pause()
			continue
		}
		if n == len(acts)+1 {
			renderHowto(hookHowto())
			pause()
			continue
		}
	}
}

// ---------------------------------------------------------------------------
//  Interactive helpers shared by tools
// ---------------------------------------------------------------------------

// promptExistingPath asks for a file path and validates it exists.
func promptExistingPath(label string) (string, bool) {
	p := prompt(label)
	p = strings.TrimSpace(p)
	if p == "" {
		warnMsg("No path entered.")
		return "", false
	}
	if !fileExists(p) {
		errMsg("File not found: " + p)
		return "", false
	}
	return p, true
}

// interactiveExport writes lastReport in a chosen format.
func interactiveExport() {
	if lastReport == nil {
		warnMsg("No report yet. Run an analysis or the demo first.")
		return
	}
	sectionHeader("Export Report")
	f := chooseFormat(prompt("format txt|md|json|csv|sarif"))
	out := prompt("output file (blank = screen)")
	writeOrShow(lastReport, f, strings.TrimSpace(out))
}

// showLastReport renders the last report to the TUI.
func showLastReport() {
	if lastReport == nil {
		warnMsg("No report yet. Run an analysis or the demo first.")
		return
	}
	sectionHeader("Last Report — " + lastReport.Target)
	for _, k := range summaryKeys(lastReport.Summary) {
		kvRow(k, lastReport.Summary[k])
	}
	fmt.Println()
	printFindingsTable(lastReport)
	gradeBanner(lastReport)
}

// runDemoInteractive runs the synthetic demo inside the TUI.
func runDemoInteractive() {
	sectionHeader("Synthetic Demo")
	info("Generating self-contained sample data...")
	rep := hookDemo()
	rep.computeGrade()
	rep.sortFindings()
	lastReport = rep
	okMsg("Demo analysis complete.")
	fmt.Println()
	for _, k := range summaryKeys(rep.Summary) {
		kvRow(k, rep.Summary[k])
	}
	fmt.Println()
	printFindingsTable(rep)
	gradeBanner(rep)
}

// analyzeInteractive prompts for a file and runs the tool's analyzer.
func analyzeInteractive() {
	sectionHeader("Analyze Input File")
	p, ok := promptExistingPath("path to capture/log file")
	if !ok {
		return
	}
	info("Analyzing " + p + " ...")
	rep, err := hookAnalyze(p)
	if err != nil {
		errMsg(err.Error())
		return
	}
	rep.computeGrade()
	rep.sortFindings()
	lastReport = rep
	okMsg("Analysis complete.")
	fmt.Println()
	for _, k := range summaryKeys(rep.Summary) {
		kvRow(k, rep.Summary[k])
	}
	fmt.Println()
	printFindingsTable(rep)
	gradeBanner(rep)
}

// ============================================================================
//  Generic 802.11 frame-crafting toolkit (offline lab + demo synthesis)
// ============================================================================

// craftWrapPcap wraps raw link-layer frames into a little-endian pcap buffer.
func craftWrapPcap(frames [][]byte, linktype int, usecStep uint32) []byte {
	var b []byte
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linktype))
	b = append(b, hdr...)
	ts := uint32(time.Now().Unix())
	us := uint32(0)
	for _, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], ts)
		binary.LittleEndian.PutUint32(rec[4:8], us)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(fr)))
		b = append(b, rec...)
		b = append(b, fr...)
		us += usecStep
		if us >= 1000000 {
			ts += us / 1000000
			us %= 1000000
		}
	}
	return b
}

// craftBeaconOpen builds a minimal open-network beacon carrying SSID + DS param.
func craftBeaconOpen(bssid []byte, ssid string, ch int) []byte {
	var f []byte
	f = append(f, 0x80, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00, 0x11, 0x00)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidDSParam, 0x01, byte(ch))
	return f
}

// craftDataEAPOL wraps an EAPOL payload inside an 802.11 data frame (LLC/SNAP).
func craftDataEAPOL(fromDS bool, ap, sta, eapol []byte) []byte {
	var f []byte
	if fromDS {
		f = append(f, 0x08, 0x02, 0x00, 0x00)
		f = append(f, sta...)
		f = append(f, ap...)
		f = append(f, sta...)
	} else {
		f = append(f, 0x08, 0x01, 0x00, 0x00)
		f = append(f, ap...)
		f = append(f, sta...)
		f = append(f, ap...)
	}
	f = append(f, 0x00, 0x00)
	f = append(f, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e)
	f = append(f, eapol...)
	return f
}

// craftProbeReq builds a probe request from a client with a directed SSID.
func craftProbeReq(client []byte, ssid string) []byte {
	var f []byte
	f = append(f, 0x40, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, client...)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, 0x00, 0x00)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidExtRates, 0x04, 0x0c, 0x12, 0x18, 0x24)
	return f
}

// craftProbeResp builds a probe response from a BSSID to a client for an SSID.
func craftProbeResp(bssid, client []byte, ssid string, ch int, privacy bool) []byte {
	var f []byte
	f = append(f, 0x50, 0x00, 0x00, 0x00)
	f = append(f, client...)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00)
	caps := uint16(0x0021)
	if privacy {
		caps |= 0x0010
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	f = append(f, cb...)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidDSParam, 0x01, byte(ch))
	return f
}

// craftBeaconSec builds a beacon with a chosen security posture (reuses RSN).
func craftBeaconSec(bssid []byte, ssid string, ch int, sec string) []byte {
	var f []byte
	f = append(f, 0x80, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00)
	caps := uint16(0x0001)
	if sec != "OPEN" {
		caps |= 0x0010
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	f = append(f, cb...)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c)
	f = append(f, eidDSParam, 0x01, byte(ch))
	switch sec {
	case "WPA2-PSK":
		f = append(f, craftRSN(2, false)...)
	case "WPA3-SAE":
		f = append(f, craftRSN(8, true)...)
	case "WPA2-Enterprise":
		f = append(f, craftRSN(1, false)...)
	}
	return f
}

func craftRSN(akm int, mfpReq bool) []byte {
	var d []byte
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, 0x04)
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, 0x04)
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, byte(akm))
	caps := uint16(0x0000)
	if mfpReq {
		caps |= 0x00c0
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	d = append(d, cb...)
	ie := []byte{eidRSN, byte(len(d))}
	return append(ie, d...)
}

// parseBeaconLike extracts SSID/channel/security from a beacon/probe-resp frame.
func parseBeaconLike(f *dot11Frame) (ssid string, ch int, sec string, hidden bool) {
	if len(f.Body) < 12 {
		return "", 0, "OPEN", false
	}
	caps := binary.LittleEndian.Uint16(f.Body[10:12])
	privacy := caps&0x0010 != 0
	ies := parseIEs(f.Body[12:])
	ssid = ieSSID(ies)
	if ssid == "<hidden>" || ssid == "" {
		hidden = true
	}
	ch = ieChannel(ies)
	var rsn rsnInfo
	if r := findIE(ies, eidRSN); r != nil {
		rsn = parseRSN(r)
	}
	sec = securityString(privacy, rsn, parseWPA1(ies))
	return ssid, ch, sec, hidden
}

// ============================================================================
//  OKarma — KARMA / evil-twin behaviour analyzer (offline)
// ============================================================================

type kaResponder struct {
	BSSID     string
	Vendor    string
	SSIDs     map[string]bool // SSIDs this BSSID responded for
	Clients   map[string]bool
	Responses int
}

type kaClient struct {
	MAC        string
	Vendor     string
	Randomized bool
	PNL        map[string]bool // directed SSIDs probed
	Probes     int
}

// kaAP is a beaconing access point observed in the capture (v1.1). Beacons
// carry the real channel + security advertisement, which is what evil-twin and
// WPA3/PMF-downgrade detection compare across BSSIDs sharing one SSID.
type kaAP struct {
	BSSID    string
	Vendor   string
	SSID     string
	Channel  int
	Security string
	WPA3     bool
	MFPCap   bool
	MFPReq   bool
	Beacons  int
}

// secTier ranks an AP's protection so a lower-tier twin of the same SSID reads
// as a downgrade. 3=WPA3/SAE+PMF-req, 2=WPA3/PMF, 1=WPA2, 0=open/WEP.
func (a *kaAP) secTier() int {
	switch {
	case a.WPA3 && a.MFPReq:
		return 3
	case a.WPA3 || a.MFPReq:
		return 2
	case strings.Contains(a.Security, "WPA2") || strings.Contains(a.Security, "WPA"):
		return 1
	default:
		return 0
	}
}

type kaResult struct {
	Target     string
	Responders map[string]*kaResponder
	Clients    map[string]*kaClient
	APs        map[string]*kaAP // v1.1: BSSID -> beaconing AP
	Frames     int
	ProbeReq   int
	ProbeResp  int
	Beacons    int
}

var kaState *kaResult

func kaAnalyzeCap(cf *capFile, target string) *kaResult {
	res := &kaResult{Target: target, Responders: map[string]*kaResponder{}, Clients: map[string]*kaClient{}, APs: map[string]*kaAP{}}
	for _, pkt := range cf.Packets {
		res.Frames++
		data := pkt.Data
		if pkt.LinkType == DLT_RADIOTAP {
			_, data = parseRadiotap(data)
		} else if pkt.LinkType == DLT_PPI && len(data) >= 8 {
			l := int(binary.LittleEndian.Uint16(data[2:4]))
			if l > 0 && l <= len(data) {
				data = data[l:]
			}
		}
		f, err := parseDot11(data)
		if err != nil || f.Type != TypeMgmt {
			continue
		}
		switch f.Subtype {
		case MgmtProbeReq:
			res.ProbeReq++
			cl := kaClientFor(res, f.Addr2)
			cl.Probes++
			ssid := ieSSID(parseIEs(f.Body))
			if ssid != "" && ssid != "<hidden>" {
				cl.PNL[ssid] = true
			}
		case MgmtProbeResp:
			res.ProbeResp++
			bssid := macStr(f.Addr3)
			r := res.Responders[bssid]
			if r == nil {
				b, _ := parseMAC(bssid)
				r = &kaResponder{BSSID: bssid, Vendor: lookupVendor(b), SSIDs: map[string]bool{}, Clients: map[string]bool{}}
				res.Responders[bssid] = r
			}
			r.Responses++
			r.Clients[macStr(f.Addr1)] = true
			ssid, _, _, _ := parseBeaconLike(f)
			if ssid != "" && ssid != "<hidden>" {
				r.SSIDs[ssid] = true
			}
		case MgmtBeacon:
			res.Beacons++
			kaRecordBeacon(res, f)
		}
	}
	kaState = res
	return res
}

// kaRecordBeacon captures a beaconing AP's advertised SSID, channel and
// security (incl. PMF/WPA3) for evil-twin and downgrade comparison (v1.1).
func kaRecordBeacon(res *kaResult, f *dot11Frame) {
	ssid, ch, sec, hidden := parseBeaconLike(f)
	if hidden || ssid == "" {
		return
	}
	bssid := macStr(f.Addr3)
	ap := res.APs[bssid]
	if ap == nil {
		b, _ := parseMAC(bssid)
		ap = &kaAP{BSSID: bssid, Vendor: lookupVendor(b), SSID: ssid, Channel: ch, Security: sec}
		res.APs[bssid] = ap
	}
	ap.Beacons++
	ap.SSID, ap.Channel, ap.Security = ssid, ch, sec
	if len(f.Body) >= 12 {
		if ies := parseIEs(f.Body[12:]); len(ies) > 0 {
			if r := findIE(ies, eidRSN); r != nil {
				ri := parseRSN(r)
				ap.WPA3 = ri.WPA3
				ap.MFPCap = ri.MFPCapable
				ap.MFPReq = ri.MFPRequired
			}
		}
	}
}

// kaBySSID groups beaconing APs by SSID (v1.1 evil-twin / downgrade core).
func kaBySSID(res *kaResult) map[string][]*kaAP {
	groups := map[string][]*kaAP{}
	for _, ap := range res.APs {
		groups[ap.SSID] = append(groups[ap.SSID], ap)
	}
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool { return g[i].secTier() > g[j].secTier() })
	}
	return groups
}

// kaEvilTwins returns SSIDs advertised by >1 BSSID, each with its AP list.
func kaEvilTwins(res *kaResult) [][]*kaAP {
	var out [][]*kaAP
	groups := kaBySSID(res)
	names := make([]string, 0, len(groups))
	for s := range groups {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		if len(groups[s]) >= 2 {
			out = append(out, groups[s])
		}
	}
	return out
}

func kaClientFor(res *kaResult, mac []byte) *kaClient {
	m := macStr(mac)
	cl := res.Clients[m]
	if cl == nil {
		cl = &kaClient{MAC: m, Vendor: lookupVendor(mac), PNL: map[string]bool{}, Randomized: macRandomizationClass(mac) == "randomized"}
		res.Clients[m] = cl
	}
	return cl
}

// kaClientExposure scores a client's trackability/evil-twin exposure 0..100.
func kaClientExposure(cl *kaClient) (int, string) {
	score := 0
	score += len(cl.PNL) * 12
	if !cl.Randomized {
		score += 20
	}
	if len(cl.PNL) >= 5 {
		score += 15
	}
	score = clampInt(score, 0, 100)
	grade := gradeFromScore(float64(100 - score))
	return score, grade
}

func kaBuildReport(res *kaResult) *Report {
	rep := newReport(res.Target)
	rep.Summary["Frames"] = strconv.Itoa(res.Frames)
	rep.Summary["Probe Requests"] = strconv.Itoa(res.ProbeReq)
	rep.Summary["Probe Responses"] = strconv.Itoa(res.ProbeResp)
	rep.Summary["Responders"] = strconv.Itoa(len(res.Responders))
	rep.Summary["Clients"] = strconv.Itoa(len(res.Clients))

	for _, r := range kaSortedResponders(res) {
		if len(r.SSIDs) >= 5 {
			rep.add(Finding{
				ID: "OKARMA-KARMA", Title: "KARMA responder (answers many SSIDs)", Severity: SevCritical, Score: 9.0,
				Entity: r.BSSID, Detail: fmt.Sprintf("BSSID %s (vendor %s) sent probe responses for %d distinct SSIDs — it impersonates every network clients ask for (KARMA/MANA).", r.BSSID, r.Vendor, len(r.SSIDs)),
				Remediation: "Clients should disable auto-join of open/known networks; use WPA3/validated 802.1X.",
				MITRE:       []string{"T1557.002", "T1557"},
			})
		} else if len(r.SSIDs) >= 2 {
			rep.add(Finding{
				ID: "OKARMA-MULTI", Title: "BSSID answering multiple SSIDs", Severity: SevHigh, Score: 7.0,
				Entity: r.BSSID, Detail: fmt.Sprintf("BSSID %s responds for %d SSIDs; possible evil-twin behaviour.", r.BSSID, len(r.SSIDs)),
				Remediation: "Verify legitimacy; a single AP normally advertises one SSID set.", MITRE: []string{"T1557.002"},
			})
		}
	}
	highExp := 0
	for _, cl := range res.Clients {
		sc, _ := kaClientExposure(cl)
		if sc >= 50 {
			highExp++
			rep.add(Finding{
				ID: "OKARMA-EXPOSED", Title: "Highly exposed client (large PNL)", Severity: SevMedium, Score: 5.5,
				Entity: cl.MAC, Detail: fmt.Sprintf("Client %s probes %d directed SSIDs (%s); exposure score %d/100 enables KARMA/evil-twin luring.", cl.MAC, len(cl.PNL), strings.Join(kaKeys(cl.PNL), ", "), sc),
				Remediation: "Remove saved open networks; forget hidden SSIDs; enable MAC randomization.",
				MITRE:       []string{"T1557.002", "T1598"},
			})
		}
	}
	rep.Summary["High-exposure Clients"] = strconv.Itoa(highExp)
	rep.Summary["Beaconing APs"] = strconv.Itoa(len(res.APs))

	// v1.1 — evil-twin by duplicate SSID + PMF/WPA3 downgrade.
	twins := 0
	for _, g := range kaEvilTwins(res) {
		twins++
		ssid := g[0].SSID
		best, worst := g[0], g[len(g)-1]
		chans := map[int]bool{}
		for _, ap := range g {
			chans[ap.Channel] = true
		}
		if best.secTier()-worst.secTier() >= 1 {
			rep.add(Finding{
				ID: "OKARMA-DOWNGRADE", Title: "WPA3/PMF downgrade twin", Severity: SevCritical, Score: 9.3,
				Entity: ssid, Detail: fmt.Sprintf("SSID %q is beaconed by %d BSSIDs with mismatched protection: %s advertises %s (PMF-req=%t, WPA3=%t) but %s advertises only %s (PMF-req=%t) — a classic downgrade/evil-twin that lures clients onto the weaker AP.", ssid, len(g), best.BSSID, best.Security, best.MFPReq, best.WPA3, worst.BSSID, worst.Security, worst.MFPReq),
				Remediation: "Enforce PMF-required (802.11w) and WPA3-only on the real SSID; alert on same-SSID BSSIDs offering weaker ciphers.",
				MITRE:       []string{"T1557.002", "T1562"},
			})
		} else {
			rep.add(Finding{
				ID: "OKARMA-TWIN", Title: "Duplicate SSID across BSSIDs", Severity: SevHigh, Score: 6.8,
				Entity: ssid, Detail: fmt.Sprintf("SSID %q is beaconed by %d distinct BSSIDs on channel(s) %s; evil-twin candidate unless this is a known multi-AP/mesh deployment.", ssid, len(g), kaChanList(chans)),
				Remediation: "Inventory authorized BSSIDs per SSID; a rogue BSSID on a different channel is a strong impersonation signal.",
				MITRE:       []string{"T1557.002"},
			})
		}
	}
	rep.Summary["Evil-twin SSIDs"] = strconv.Itoa(twins)
	rep.TextBody = kaTextBody(res)
	return rep
}

func kaChanList(m map[int]bool) string {
	out := []int{}
	for c := range m {
		out = append(out, c)
	}
	sort.Ints(out)
	parts := make([]string, len(out))
	for i, c := range out {
		parts[i] = strconv.Itoa(c)
	}
	return strings.Join(parts, ",")
}

func kaTextBody(res *kaResult) string {
	var sb strings.Builder
	sb.WriteString("RESPONDERS (potential evil-twin / KARMA)\n")
	sb.WriteString(fmt.Sprintf("%-18s %-10s %-7s %s\n", "BSSID", "VENDOR", "SSIDs", "SSID SAMPLES"))
	for _, r := range kaSortedResponders(res) {
		sb.WriteString(fmt.Sprintf("%-18s %-10s %-7d %s\n", r.BSSID, truncStr(r.Vendor, 10), len(r.SSIDs), truncStr(strings.Join(kaKeys(r.SSIDs), ","), 40)))
	}
	sb.WriteString("\nCLIENT EXPOSURE\n")
	for _, cl := range res.Clients {
		sc, g := kaClientExposure(cl)
		rnd := ""
		if cl.Randomized {
			rnd = " [random]"
		}
		sb.WriteString(fmt.Sprintf("  %-18s PNL=%-2d exposure=%-3d grade=%s%s\n", cl.MAC, len(cl.PNL), sc, g, rnd))
	}
	return sb.String()
}

func kaSortedResponders(res *kaResult) []*kaResponder {
	out := []*kaResponder{}
	for _, r := range res.Responders {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].SSIDs) > len(out[j].SSIDs) })
	return out
}

func kaKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- v1.1 exports ----------------------------------------------------------

// kaWatchlist builds a defender watchlist of suspicious BSSIDs (KARMA / multi-
// SSID responders, evil-twins, downgrade twins) with the reason for each.
func kaWatchlist(res *kaResult) [][]string {
	rows := [][]string{}
	seen := map[string]bool{}
	add := func(bssid, vendor, reason string) {
		key := bssid + "|" + reason
		if seen[key] {
			return
		}
		seen[key] = true
		rows = append(rows, []string{bssid, vendor, reason})
	}
	for _, r := range kaSortedResponders(res) {
		switch {
		case len(r.SSIDs) >= 5:
			add(r.BSSID, r.Vendor, fmt.Sprintf("KARMA responder (%d SSIDs)", len(r.SSIDs)))
		case len(r.SSIDs) >= 2:
			add(r.BSSID, r.Vendor, fmt.Sprintf("multi-SSID responder (%d SSIDs)", len(r.SSIDs)))
		}
	}
	for _, g := range kaEvilTwins(res) {
		best, worst := g[0], g[len(g)-1]
		for _, ap := range g {
			reason := fmt.Sprintf("evil-twin of %q", ap.SSID)
			if best.secTier()-worst.secTier() >= 1 && ap.secTier() < best.secTier() {
				reason = fmt.Sprintf("DOWNGRADE twin of %q (%s)", ap.SSID, ap.Security)
			}
			add(ap.BSSID, ap.Vendor, reason)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return rows
}

func exportWatchlist(res *kaResult, path string) error {
	rows := kaWatchlist(res)
	var sb strings.Builder
	sb.WriteString("# OKarma watchlist — authorized monitoring only\n")
	sb.WriteString("bssid,vendor,reason\n")
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("%s,%s,%s\n", r[0], r[1], strings.ReplaceAll(r[2], ",", ";")))
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// kaProbeMap returns client -> directed SSID pairs (the Preferred Network List
// reconstruction) for the client->SSID map feature.
func kaProbeMap(res *kaResult) [][]string {
	rows := [][]string{}
	macs := make([]string, 0, len(res.Clients))
	for m := range res.Clients {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	for _, m := range macs {
		cl := res.Clients[m]
		for _, s := range kaKeys(cl.PNL) {
			rows = append(rows, []string{m, s})
		}
	}
	return rows
}

func exportProbeMap(res *kaResult, path string) error {
	var sb strings.Builder
	sb.WriteString("client,ssid\n")
	for _, r := range kaProbeMap(res) {
		sb.WriteString(fmt.Sprintf("%s,%s\n", r[0], strings.ReplaceAll(r[1], ",", ";")))
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func kaViewTwins() {
	if kaState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	sectionHeader("Evil-Twin / Downgrade Groups")
	twins := kaEvilTwins(kaState)
	if len(twins) == 0 {
		warnMsg("No SSID is beaconed by more than one BSSID.")
		return
	}
	for _, g := range twins {
		best, worst := g[0], g[len(g)-1]
		tag := "evil-twin"
		if best.secTier()-worst.secTier() >= 1 {
			tag = "DOWNGRADE"
		}
		fmt.Println("  " + col(g[0].SSID, B+CY) + col("  ["+tag+"]", YLW))
		rows := [][]string{}
		for _, ap := range g {
			pmf := "no"
			if ap.MFPReq {
				pmf = "req"
			} else if ap.MFPCap {
				pmf = "cap"
			}
			rows = append(rows, []string{ap.BSSID, truncStr(ap.Vendor, 12), strconv.Itoa(ap.Channel), truncStr(ap.Security, 18), pmf})
		}
		table([]string{"BSSID", "VENDOR", "CH", "SECURITY", "PMF"}, rows)
	}
}

func kaViewProbeMap() {
	if kaState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	sectionHeader("Client → SSID Probe Map")
	rows := kaProbeMap(kaState)
	if len(rows) == 0 {
		warnMsg("No directed probe requests observed.")
		return
	}
	table([]string{"CLIENT", "DIRECTED SSID"}, rows)
}

func kaExportWatchlistInteractive() {
	if kaState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	path := prompt("Watchlist output path [watchlist.csv]: ")
	if strings.TrimSpace(path) == "" {
		path = "watchlist.csv"
	}
	if err := exportWatchlist(kaState, path); err != nil {
		errMsg(err.Error())
		return
	}
	okMsg(fmt.Sprintf("Wrote %d watchlist row(s) to %s", len(kaWatchlist(kaState)), path))
}

func kaExportProbeMapInteractive() {
	if kaState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	path := prompt("Probe-map output path [probemap.csv]: ")
	if strings.TrimSpace(path) == "" {
		path = "probemap.csv"
	}
	if err := exportProbeMap(kaState, path); err != nil {
		errMsg(err.Error())
		return
	}
	okMsg(fmt.Sprintf("Wrote %d client→SSID pair(s) to %s", len(kaProbeMap(kaState)), path))
}

// ---- synthetic capture ----------------------------------------------------

func kaSynthCapture() []byte {
	karma := []byte{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01}
	legit := []byte{0x00, 0x1a, 0x2b, 0x11, 0x22, 0x33}
	clients := [][]byte{
		{0x3c, 0x07, 0x54, 0xaa, 0xbb, 0xcc},
		{0xf0, 0xdb, 0xf8, 0x44, 0x55, 0x66},
		{0xda, 0xa1, 0x19, 0x77, 0x88, 0x99},
	}
	pnl := []string{"HomeNet", "StarbucksWiFi", "AirportFree", "Office_Guest", "Hotel123", "CorpNet"}
	var frames [][]byte
	for _, cl := range clients {
		for _, s := range pnl {
			frames = append(frames, craftProbeReq(cl, s))
			// KARMA box answers every probe
			frames = append(frames, craftProbeResp(karma, cl, s, 6, false))
		}
	}
	// legit AP answers only its own SSID
	for _, cl := range clients {
		frames = append(frames, craftProbeResp(legit, cl, "CorpNet", 6, true))
	}
	// v1.1: a real WPA3/PMF-required CorpNet beacon, plus a rogue twin that
	// beacons the same SSID on another channel with only WPA2 (downgrade).
	rogue := []byte{0x02, 0xca, 0xfe, 0xba, 0xbe, 0x02}
	for i := 0; i < 3; i++ {
		frames = append(frames, craftBeaconSec(legit, "CorpNet", 6, "WPA3-SAE"))
		frames = append(frames, craftBeaconSec(rogue, "CorpNet", 11, "WPA2-PSK"))
	}
	return craftWrapPcap(frames, DLT_IEEE802_11, 3000)
}

// ---- hooks ----------------------------------------------------------------

func kaViewResponders() {
	if kaState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	sectionHeader("Responders / Evil-Twin Candidates")
	rows := [][]string{}
	for _, r := range kaSortedResponders(kaState) {
		rows = append(rows, []string{r.BSSID, truncStr(r.Vendor, 12), strconv.Itoa(len(r.SSIDs)), strconv.Itoa(len(r.Clients))})
	}
	table([]string{"BSSID", "VENDOR", "SSIDs", "CLIENTS"}, rows)
}

func kaViewClients() {
	if kaState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	sectionHeader("Client Exposure")
	rows := [][]string{}
	for _, cl := range kaState.Clients {
		sc, g := kaClientExposure(cl)
		rnd := "no"
		if cl.Randomized {
			rnd = "yes"
		}
		rows = append(rows, []string{cl.MAC, truncStr(cl.Vendor, 12), strconv.Itoa(len(cl.PNL)), strconv.Itoa(sc), g, rnd})
	}
	table([]string{"CLIENT", "VENDOR", "PNL", "EXPOSURE", "GRADE", "RANDOM"}, rows)
}

var (
	kaFlagWatchlist string
	kaFlagProbemap  string
)

func kaRegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&kaFlagWatchlist, "watchlist", "", "export suspicious-BSSID watchlist CSV")
	fs.StringVar(&kaFlagProbemap, "probemap", "", "export client→SSID probe map CSV")
}

func kaAnalyzePath(path string) (*Report, error) {
	cf, err := loadCapture(path)
	if err != nil {
		return nil, err
	}
	res := kaAnalyzeCap(cf, filepath.Base(path))
	rep := kaBuildReport(res)
	if err := kaMaybeExport(res); err != nil {
		return nil, err
	}
	return rep, nil
}

// kaMaybeExport honors --watchlist/--probemap after any analysis (incl. demo).
func kaMaybeExport(res *kaResult) error {
	if kaFlagWatchlist != "" {
		if err := exportWatchlist(res, kaFlagWatchlist); err != nil {
			return err
		}
		okMsg("Watchlist written to " + kaFlagWatchlist)
	}
	if kaFlagProbemap != "" {
		if err := exportProbeMap(res, kaFlagProbemap); err != nil {
			return err
		}
		okMsg("Probe map written to " + kaFlagProbemap)
	}
	return nil
}

func kaDemoReport() *Report {
	cf, err := parseCaptureBytes(kaSynthCapture())
	if err != nil {
		r := newReport("synthetic-demo")
		r.add(Finding{Title: "demo error", Detail: err.Error(), Severity: SevInfo})
		return r
	}
	res := kaAnalyzeCap(cf, "synthetic-demo")
	rep := kaBuildReport(res)
	if err := kaMaybeExport(res); err != nil {
		errMsg(err.Error())
	}
	return rep
}

func kaHowto() []howSection {
	return []howSection{
		{"LEGAL & ETHICAL WARNING", legalWarningLines()},
		{"HOW TO USE", []string{
			"OKarma detects KARMA/MANA and evil-twin behaviour and scores client",
			"exposure, entirely from offline captures.",
			"",
			"1. Capture probe requests and responses in monitor mode.",
			"2. Run:  okarma --input capture.pcap",
			"3. Review responders answering many SSIDs (KARMA) and exposed clients.",
			"4. Export:  --format md --output karma.md",
			"5. Demo:  okarma --demo.",
		}},
		{"NAVIGATION", navigationLines([]string{
			"Analyze capture", "Run synthetic demo", "View responders",
			"View client exposure", "View evil-twin / downgrade groups",
			"View client→SSID probe map", "Export watchlist (CSV)",
			"Export probe map (CSV)", "Show last report", "Export report",
		})},
		{"v1.1 FEATURES & FLAGS", []string{
			"- Evil-twin by duplicate SSID: beacons grouped by SSID; >1 BSSID = twin.",
			"- WPA3/PMF downgrade: same SSID offered at a weaker tier flags CRITICAL.",
			"- --watchlist out.csv  export suspicious BSSIDs (bssid,vendor,reason).",
			"- --probemap out.csv   export client→directed-SSID pairs (PNL recon).",
			"- Example:  okarma --input cap.pcap --watchlist wl.csv --probemap pm.csv",
		}},
		{"REQUIREMENTS", []string{
			"- A pcap/pcapng with probe requests/responses and/or beacons.",
			"- Beacons are needed for evil-twin and PMF/WPA3 downgrade detection.",
			"- Offline only; no frames are transmitted.",
		}},
		{"PROTOCOL NOTES", []string{
			"- KARMA: an AP answers ANY directed probe, impersonating all SSIDs.",
			"- A legitimate AP responds only for its own SSID set.",
			"- Evil-twin: same SSID beaconed by an unauthorized BSSID/channel.",
			"- Downgrade: a twin offering WPA2/open where the real AP is WPA3+PMF.",
			"- Client exposure rises with PNL size and non-randomized MAC.",
			"- Mitigations: WPA3, PMF-required (802.11w), validated 802.1X.",
		}},
	}
}

func kaActions() []menuAction {
	return []menuAction{
		{"Analyze capture", analyzeInteractive},
		{"Run synthetic demo", runDemoInteractive},
		{"View responders", kaViewResponders},
		{"View client exposure", kaViewClients},
		{"View evil-twin / downgrade groups", kaViewTwins},
		{"View client→SSID probe map", kaViewProbeMap},
		{"Export watchlist (CSV)", kaExportWatchlistInteractive},
		{"Export probe map (CSV)", kaExportProbeMapInteractive},
		{"Show last report", showLastReport},
		{"Export report", interactiveExport},
	}
}

func init() {
	hookHowto = kaHowto
	hookDemo = kaDemoReport
	hookAnalyze = kaAnalyzePath
	hookActions = kaActions
	hookRegisterFlags = kaRegisterFlags
}

// ====================================================================
//  SELF-TEST — verifies the 802.11 parsers, KARMA detector & exporters.
// ====================================================================

func runSelfTest() int {
	banner()
	fmt.Println("  " + col("⬡  Self-Test — "+APPNAME+" engine", B+CY))
	rule()
	fmt.Println()
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
		}
	}

	// MAC parser.
	mac, err := parseMAC("00:11:22:aa:bb:cc")
	check("parseMAC colon form", err == nil && len(mac) == 6 && mac[0] == 0x00 && mac[5] == 0xcc)
	mac2, err2 := parseMAC("00.11.22.aa.bb.cc")
	check("parseMAC dotted form", err2 == nil && len(mac2) == 6 && mac2[3] == 0xaa)
	mac3, err3 := parseMAC("001122aabbcc")
	check("parseMAC bare 12-nibble form", err3 == nil && len(mac3) == 6)
	_, errBad := parseMAC("nope")
	check("parseMAC rejects garbage", errBad != nil)

	// hex dump parser.
	hb, errH := parseHexDump("de ad be ef")
	check("parseHexDump reads spaced hex", errH == nil && len(hb) == 4 && hb[0] == 0xde && hb[3] == 0xef)

	// severity mapping is monotonic.
	check("scoreToSeverity high score ≥ low score severity",
		scoreToSeverity(90) != "" && scoreToSeverity(1) != "" && scoreToSeverity(90) != scoreToSeverity(1))

	// demo report via the real hook.
	rep := hookDemo()
	check("hookDemo returns a report", rep != nil)
	if rep != nil {
		rep.computeGrade()
		rep.sortFindings()
		check("demo report has findings", len(rep.Findings) > 0)
		check("demo report is graded", rep.Grade != "")
		// findings sorted by score descending.
		sorted := true
		for i := 1; i < len(rep.Findings); i++ {
			if rep.Findings[i-1].Score < rep.Findings[i].Score {
				sorted = false
				break
			}
		}
		check("findings sorted by score (desc)", sorted)
		// every finding has an ID and title.
		fieldsOK := true
		for _, f := range rep.Findings {
			if f.ID == "" || f.Title == "" {
				fieldsOK = false
			}
		}
		check("every demo finding has ID + title", fieldsOK)

		// exporters.
		for _, fmtName := range []string{"txt", "md", "json", "csv", "sarif"} {
			out, e := renderReport(rep, fmtName)
			check("renderReport("+fmtName+") produces output", e == nil && len(strings.TrimSpace(out)) > 0)
		}
		js, _ := renderReport(rep, "json")
		var parsed interface{}
		check("JSON export is valid JSON", json.Unmarshal([]byte(js), &parsed) == nil)
		sarif, _ := renderReport(rep, "sarif")
		var sp map[string]interface{}
		check("SARIF export is valid JSON", json.Unmarshal([]byte(sarif), &sp) == nil)
	}

	// howto + actions hooks are wired.
	check("hookHowto returns sections", len(hookHowto()) > 0)
	check("hookActions returns menu actions", len(hookActions()) > 0)

	// v1.1 — beacon capture, evil-twin, downgrade, exports.
	cf, _ := parseCaptureBytes(kaSynthCapture())
	res := kaAnalyzeCap(cf, "selftest")
	check("beacons captured into APs", res.Beacons > 0 && len(res.APs) >= 2)
	twins := kaEvilTwins(res)
	check("evil-twin duplicate SSID detected", len(twins) >= 1)
	downgrade := false
	for _, g := range twins {
		if g[0].secTier()-g[len(g)-1].secTier() >= 1 {
			downgrade = true
		}
	}
	check("WPA3/PMF downgrade twin detected", downgrade)
	rep2 := kaBuildReport(res)
	hasDown, hasKarma := false, false
	for _, f := range rep2.Findings {
		if f.ID == "OKARMA-DOWNGRADE" {
			hasDown = true
		}
		if f.ID == "OKARMA-KARMA" {
			hasKarma = true
		}
	}
	check("report emits DOWNGRADE finding", hasDown)
	check("report still emits KARMA finding", hasKarma)
	wl := kaWatchlist(res)
	check("watchlist lists suspicious BSSIDs", len(wl) >= 2)
	pm := kaProbeMap(res)
	check("probe map reconstructs client→SSID pairs", len(pm) > 0)
	secHi := (&kaAP{WPA3: true, MFPReq: true}).secTier()
	secLo := (&kaAP{Security: "WPA2-PSK"}).secTier()
	check("secTier ranks WPA3+PMF above WPA2", secHi > secLo)

	// UI helpers.
	check("stripANSI removes colour", stripANSI(col("hi", CY)) == "hi")
	check("visw counts runes", visw("abc") == 3)

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}
