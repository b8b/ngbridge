package cbpf

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

type pcapFilter struct {
	name   string
	filter Filter
	expr   string
}

func pcapFilters(t *testing.T) []pcapFilter {
	t.Helper()
	jailMAC := mustMAC(t, "02:00:00:00:00:01")
	hostMAC := mustMAC(t, "02:00:00:00:00:02")
	jailIP := mustIP(t, "10.0.0.5")
	otherIP := mustIP(t, "10.0.0.7")
	hostIP := mustIP(t, "10.0.0.1")
	multicastNet := mustCIDR(t, "224.0.0.0/4")

	return []pcapFilter{
		{"ether src", EtherSrc(jailMAC), "ether src 02:00:00:00:00:01"},
		{"ether dst", EtherDst(hostMAC), "ether dst 02:00:00:00:00:02"},
		{"ether src and dst", And(EtherSrc(jailMAC), EtherDst(hostMAC)),
			"ether src 02:00:00:00:00:01 and ether dst 02:00:00:00:00:02"},
		{"dst host", IPDst(hostIP), "dst host 10.0.0.1"},
		{"src host", IPSrc(jailIP), "src host 10.0.0.5"},
		{"src hosts", Or(IPSrc(jailIP), IPSrc(otherIP)),
			"src host 10.0.0.5 or src host 10.0.0.7"},
		{"ipv4 src host", IPv4Src(jailIP), "ip and src host 10.0.0.5"},
		{"ipv4 dst host", IPv4Dst(hostIP), "ip and dst host 10.0.0.1"},
		{"dst net", IPv4DstNet(mustCIDR(t, "10.0.0.0/24")), "dst net 10.0.0.0/24"},
		{"dst net any", IPv4DstNet(mustCIDR(t, "0.0.0.0/0")), "dst net 0.0.0.0/0"},
		{"ip multicast", IPv4Multicast(), "ip multicast"},
		{"ether broadcast", EtherBroadcast(), "ether broadcast"},
		{"ether multicast", EtherMulticast(), "ether multicast"},
		{"jail to bridge", And(EtherSrc(jailMAC), Or(IPSrc(jailIP))),
			"ether src 02:00:00:00:00:01 and (src host 10.0.0.5)"},
		{"multicast restriction",
			Or(EtherBroadcast(), Not(EtherMulticast()), IPv4DstNet(multicastNet)),
			"ether broadcast or not ether multicast or dst net 224.0.0.0/4"},
	}
}

func tcpdumpPath(t *testing.T) string {
	t.Helper()
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("tcpdump not installed")
	}
	return tcpdump
}

func TestFiltersMatchLibpcap(t *testing.T) {
	tcpdump := tcpdumpPath(t)
	frames := testFrames(t)
	for _, pf := range pcapFilters(t) {
		t.Run(pf.name, func(t *testing.T) {
			ours, err := Compile(pf.filter, 0)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			ourVM, err := bpf.NewVM(mustDisassemble(t, ours.Instructions()))
			if err != nil {
				t.Fatalf("our vm: %v", err)
			}
			theirs := libpcapProgram(t, tcpdump, pf.expr)
			theirVM, err := bpf.NewVM(mustDisassemble(t, theirs))
			if err != nil {
				t.Fatalf("libpcap vm: %v", err)
			}
			for _, fr := range frames {
				want := run(theirVM, fr.data)
				if got := run(ourVM, fr.data); got != want {
					t.Errorf("%q (%d instructions, libpcap %d): got match=%v, want %v\nours:\n%s\nlibpcap:\n%s",
						fr.name, ours.Len(), len(theirs), got, want,
						mustDisassembly(t, ours), mustDisassemblyRaw(t, theirs))
				}
			}
		})
	}
}

func run(vm *bpf.VM, frame []byte) bool {
	n, err := vm.Run(frame)
	return err == nil && n > 0
}

func mustDisassemble(t *testing.T, raw []bpf.RawInstruction) []bpf.Instruction {
	t.Helper()
	insns, complete := bpf.Disassemble(raw)
	if !complete {
		t.Fatalf("incomplete disassembly of %v", raw)
	}
	return insns
}

func mustDisassembly(t *testing.T, p *Program) string {
	t.Helper()
	out, err := p.Disassembly()
	if err != nil {
		t.Fatalf("disassemble: %v", err)
	}
	return out
}

func mustDisassemblyRaw(t *testing.T, raw []bpf.RawInstruction) string {
	t.Helper()
	var b strings.Builder
	for i, in := range raw {
		fmt.Fprintf(&b, "%03d code=%d jt=%d jf=%d k=%d\n", i, in.Op, in.Jt, in.Jf, in.K)
	}
	return b.String()
}

func libpcapProgram(t *testing.T, tcpdump, expr string) []bpf.RawInstruction {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(tcpdump, "-ddd", "-y", "EN10MB", expr)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tcpdump %q: %v: %s", expr, err, stderr.String())
	}
	return parseDDD(t, stdout.String())
}

func parseDDD(t *testing.T, out string) []bpf.RawInstruction {
	t.Helper()
	scan := bufio.NewScanner(strings.NewReader(out))
	if !scan.Scan() {
		t.Fatalf("empty tcpdump output")
	}
	want, err := strconv.Atoi(strings.TrimSpace(scan.Text()))
	if err != nil {
		t.Fatalf("parse instruction count %q: %v", scan.Text(), err)
	}
	var insns []bpf.RawInstruction
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) != 4 {
			t.Fatalf("unexpected tcpdump line %q", scan.Text())
		}
		code, _ := strconv.ParseUint(fields[0], 10, 16)
		jt, _ := strconv.ParseUint(fields[1], 10, 8)
		jf, _ := strconv.ParseUint(fields[2], 10, 8)
		k, _ := strconv.ParseUint(fields[3], 10, 32)
		insns = append(insns, bpf.RawInstruction{
			Op: uint16(code),
			Jt: uint8(jt),
			Jf: uint8(jf),
			K:  uint32(k),
		})
	}
	if len(insns) != want {
		t.Fatalf("tcpdump announced %d instructions, parsed %d", want, len(insns))
	}
	return insns
}

// parsedExpressions are pcap filter expressions that Parse must accept, with
// libpcap deciding what they mean.
func parsedExpressions() []string {
	return []string{
		"ip",
		"arp",
		"rarp",
		"ip src host 10.0.0.5",
		"ip dst host 10.0.0.1",
		"arp src host 10.0.0.5",
		"rarp dst host 10.0.0.1",
		"src host 10.0.0.5",
		"dst host 10.0.0.1",
		"host 10.0.0.1",
		"dst 10.0.0.1",
		"ip host 10.0.0.5",
		"src net 10.0.0.0/24",
		"dst net 10.0.0.0/24",
		"net 10.0.0.0/24",
		"ip src net 10.0.0.0/8",
		"ip dst net 224.0.0.0/4",
		"ether src 02:00:00:00:00:01",
		"ether dst 02:00:00:00:00:02",
		"ether host 02:00:00:00:00:01",
		"ether broadcast",
		"ether multicast",
		"broadcast",
		"multicast",
		"ip multicast",
		"not ether multicast",
		"ip and dst host 10.0.0.1",
		"ip or arp",
		"(ip or arp) and src host 10.0.0.5",
		"not (ip or arp)",
		"ip",
		"ether src 02:00:00:00:00:01 and not ip",
		"ip net 10.0.0.0/24 or ether broadcast",
		"ether src 02:00:00:00:00:01 and src host 10.0.0.5",
		"ether src 02:00:00:00:00:01 and ip src host 10.0.0.5",
		"ether src 02:00:00:00:00:01 and arp and src host 10.0.0.5",
		"dst host 10.0.0.1 or arp",
		"src host 10.0.0.5 && dst host 10.0.0.1",
		"! ether multicast",
		"len >= 0",
		"len < 0",
		"1=1",
	}
}

func TestParseMatchesLibpcap(t *testing.T) {
	tcpdump := tcpdumpPath(t)
	frames := testFrames(t)
	for _, expression := range parsedExpressions() {
		t.Run(expression, func(t *testing.T) {
			filter, err := Parse(expression)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ours, err := Compile(filter, 0)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			ourVM, err := bpf.NewVM(mustDisassemble(t, ours.Instructions()))
			if err != nil {
				t.Fatalf("our vm: %v", err)
			}
			theirs := libpcapProgram(t, tcpdump, expression)
			theirVM, err := bpf.NewVM(mustDisassemble(t, theirs))
			if err != nil {
				t.Fatalf("libpcap vm: %v", err)
			}
			for _, fr := range frames {
				want := run(theirVM, fr.data)
				if got := run(ourVM, fr.data); got != want {
					t.Errorf("%q (%d instructions, libpcap %d): got match=%v, want %v\nours:\n%s\nlibpcap:\n%s",
						fr.name, ours.Len(), len(theirs), got, want,
						mustDisassembly(t, ours), mustDisassemblyRaw(t, theirs))
				}
			}
		})
	}
}
