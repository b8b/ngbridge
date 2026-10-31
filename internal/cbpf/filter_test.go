package cbpf

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("parse mac %q: %v", s, err)
	}
	return mac
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("parse ip %q", s)
	}
	return ip
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse cidr %q: %v", s, err)
	}
	return n
}

func ethernetFrame(dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func arpPayload(op uint16, senderMAC, targetMAC net.HardwareAddr, senderIP, targetIP net.IP) []byte {
	payload := make([]byte, 28)
	binary.BigEndian.PutUint16(payload[0:2], 1)
	binary.BigEndian.PutUint16(payload[2:4], 0x0800)
	payload[4] = 6
	payload[5] = 4
	binary.BigEndian.PutUint16(payload[6:8], op)
	copy(payload[8:14], senderMAC)
	copy(payload[14:18], senderIP.To4())
	copy(payload[18:24], targetMAC)
	copy(payload[24:28], targetIP.To4())
	return payload
}

func ipv4Payload(protocol byte, src, dst net.IP, l4 []byte) []byte {
	payload := make([]byte, 20+len(l4))
	payload[0] = 0x45
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))
	payload[8] = 64
	payload[9] = protocol
	copy(payload[12:16], src.To4())
	copy(payload[16:20], dst.To4())
	copy(payload[20:], l4)
	return payload
}

type frame struct {
	name string
	data []byte
}

func testFrames(t *testing.T) []frame {
	t.Helper()
	jailMAC := mustMAC(t, "02:00:00:00:00:01")
	hostMAC := mustMAC(t, "02:00:00:00:00:02")
	otherMAC := mustMAC(t, "02:00:00:00:00:03")
	broadcastMAC := mustMAC(t, "ff:ff:ff:ff:ff:ff")
	multicastMAC := mustMAC(t, "01:00:5e:00:00:01")

	jailIP := mustIP(t, "10.0.0.5")
	hostIP := mustIP(t, "10.0.0.1")
	otherIP := mustIP(t, "10.0.0.7")
	multicastIP := mustIP(t, "224.0.0.5")

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 80)
	binary.BigEndian.PutUint16(tcp[2:4], 443)

	return []frame{
		{"arp request jail to host", ethernetFrame(broadcastMAC, jailMAC, etherTypeARP,
			arpPayload(1, jailMAC, broadcastMAC, jailIP, hostIP))},
		{"arp reply host to jail", ethernetFrame(jailMAC, hostMAC, etherTypeARP,
			arpPayload(2, hostMAC, jailMAC, hostIP, jailIP))},
		{"rarp jail to host", ethernetFrame(hostMAC, jailMAC, etherTypeRARP,
			arpPayload(3, jailMAC, hostMAC, jailIP, hostIP))},
		{"ipv4 tcp jail to host", ethernetFrame(hostMAC, jailMAC, etherTypeIPv4,
			ipv4Payload(6, jailIP, hostIP, tcp))},
		{"ipv4 tcp host to jail", ethernetFrame(jailMAC, hostMAC, etherTypeIPv4,
			ipv4Payload(6, hostIP, jailIP, tcp))},
		{"ipv4 tcp other source", ethernetFrame(hostMAC, otherMAC, etherTypeIPv4,
			ipv4Payload(6, otherIP, hostIP, tcp))},
		{"ipv4 multicast", ethernetFrame(multicastMAC, hostMAC, etherTypeIPv4,
			ipv4Payload(17, hostIP, multicastIP, tcp))},
		{"ipv4 broadcast", ethernetFrame(broadcastMAC, hostMAC, etherTypeIPv4,
			ipv4Payload(17, hostIP, mustIP(t, "10.0.0.255"), tcp))},
		{"ipv6 tcp jail to host", ethernetFrame(hostMAC, jailMAC, 0x86dd,
			append([]byte{0x60, 0, 0, 0, 0, 20, 6, 64}, append(jailIP.To16(), hostIP.To16()...)...))},
		{"short frame", []byte{0x01, 0x02, 0x03}},
	}
}

func TestNGctlProgram(t *testing.T) {
	prog, err := Compile(All(), 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := prog.NGctlProgram("jail", "bridge", "")
	if err != nil {
		t.Fatalf("ngctl program: %v", err)
	}
	want := `{ thisHook="jail" ifMatch="bridge" ifNotMatch="" bpf_prog_len=2 bpf_prog=[ { code=6 jt=0 jf=0 k=262144 } { code=6 jt=0 jf=0 k=0 } ] }`
	if got != want {
		t.Errorf("ngctl program:\n got %s\nwant %s", got, want)
	}
}

func TestNGctlProgramRejectsBadHookNames(t *testing.T) {
	prog, err := Compile(All(), 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, hook := range []string{
		"0123456789012345678901234567890123",
		`with"quote`,
		"with space",
	} {
		if _, err := prog.NGctlProgram(hook, "", ""); err == nil {
			t.Errorf("hook %q: expected an error", hook)
		}
	}
}

func TestEmptyCriteriaMatchEverything(t *testing.T) {
	for name, f := range map[string]Filter{
		"no ether src": EtherSrc(),
		"no ether dst": EtherDst(),
		"no src ip":    IPSrc(),
		"no and":       And(),
	} {
		prog, err := Compile(f, 0)
		if err != nil {
			t.Fatalf("%s: compile: %v", name, err)
		}
		if prog.Len() != 2 {
			t.Errorf("%s: got %d instructions, want 2", name, prog.Len())
		}
	}
}

func TestNoneMatchesNothing(t *testing.T) {
	prog, err := Compile(None(), 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	vm, err := bpf.NewVM(mustDisassemble(t, prog.Instructions()))
	if err != nil {
		t.Fatalf("vm: %v", err)
	}
	for _, fr := range testFrames(t) {
		if run(vm, fr.data) {
			t.Errorf("%q: matched, want no match", fr.name)
		}
	}
}

func TestRejectsNonIPv4Addresses(t *testing.T) {
	v6 := mustIP(t, "2001:db8::1")
	for name, f := range map[string]Filter{
		"src host":   IPSrc(v6),
		"dst host":   IPDst(v6),
		"ipv4 src":   IPv4Src(v6),
		"dst net v6": IPv4DstNet(&net.IPNet{IP: v6, Mask: net.CIDRMask(64, 128)}),
	} {
		if _, err := Compile(f, 0); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Compile(EtherSrc(net.HardwareAddr{1, 2, 3}), 0); err == nil {
		t.Error("short mac: expected an error")
	}
}

func TestZeroMaskMatchesAnyIPv4(t *testing.T) {
	prog, err := Compile(IPv4DstNet(mustCIDR(t, "0.0.0.0/0")), 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	vm, err := bpf.NewVM(mustDisassemble(t, prog.Instructions()))
	if err != nil {
		t.Fatalf("vm: %v", err)
	}
	for _, fr := range testFrames(t) {
		want := !strings.Contains(fr.name, "ipv6") && !strings.Contains(fr.name, "short")
		if got := run(vm, fr.data); got != want {
			t.Errorf("%q: got match=%v, want %v", fr.name, got, want)
		}
	}
}
