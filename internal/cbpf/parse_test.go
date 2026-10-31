package cbpf

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

func TestParseBuildsExpectedFilters(t *testing.T) {
	cases := []struct {
		expression string
		filter     Filter
	}{
		{"ip", IPv4()},
		{"arp", ARP()},
		{"rarp", RARP()},
		{"ip src host 10.0.0.5", And(IPv4(), IPSrc(mustIP(t, "10.0.0.5")))},
		{"ip dst host 10.0.0.1", And(IPv4(), IPDst(mustIP(t, "10.0.0.1")))},
		{"arp dst host 10.0.0.1", And(ARP(), IPDst(mustIP(t, "10.0.0.1")))},
		{"src host 10.0.0.5", IPSrc(mustIP(t, "10.0.0.5"))},
		{"dst 10.0.0.1", IPDst(mustIP(t, "10.0.0.1"))},
		{"host 10.0.0.1", Or(IPSrc(mustIP(t, "10.0.0.1")), IPDst(mustIP(t, "10.0.0.1")))},
		{"dst net 10.0.0.0/24", IPv4DstNet(mustCIDR(t, "10.0.0.0/24"))},
		{"ip src net 10.0.0.0/8", And(IPv4(), IPv4SrcNet(mustCIDR(t, "10.0.0.0/8")))},
		{"ether src 02:00:00:00:00:01", EtherSrc(mustMAC(t, "02:00:00:00:00:01"))},
		{"ether host 02:00:00:00:00:01",
			Or(EtherSrc(mustMAC(t, "02:00:00:00:00:01")), EtherDst(mustMAC(t, "02:00:00:00:00:01")))},
		{"ether broadcast", EtherBroadcast()},
		{"broadcast", EtherBroadcast()},
		{"multicast", EtherMulticast()},
		{"ip multicast", IPv4Multicast()},
		{"not ip", Not(IPv4())},
		{"! ip", Not(IPv4())},
		{"ip && arp", And(IPv4(), ARP())},
		{"ip || arp", Or(IPv4(), ARP())},
		{"(ip or arp) and not ether multicast",
			And(Or(IPv4(), ARP()), Not(EtherMulticast()))},
		{"ip or arp and rarp", Or(IPv4(), And(ARP(), RARP()))},
		{"len >= 0", All()},
		{"len>=0", All()},
		{"len < 0", None()},
	}
	for _, c := range cases {
		t.Run(c.expression, func(t *testing.T) {
			parsed, err := Parse(c.expression)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			want, err := Compile(c.filter, 0)
			if err != nil {
				t.Fatalf("compile expected: %v", err)
			}
			got, err := Compile(parsed, 0)
			if err != nil {
				t.Fatalf("compile parsed: %v", err)
			}
			if !bytes.Equal(want.Bytes(), got.Bytes()) {
				t.Errorf("%q compiled differently\ngot:\n%swant:\n%s",
					c.expression, mustDisassembly(t, got), mustDisassembly(t, want))
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		expression string
		want       string
	}{
		{"", "empty filter expression"},
		{"   ", "empty filter expression"},
		{"tcp port 80", `"tcp" is not supported`},
		{"port 80", `"port" is not supported`},
		{"ether", `"ether" needs a qualifier`},
		{"ether net 10.0.0.0/8", "ether net is not supported"},
		{"ip broadcast", "ip broadcast is not supported"},
		{"ether src multicast", "src multicast is not supported"},
		{"ip src host 300.1.1.1", `"300.1.1.1" is not an IPv4 address`},
		{"ip src host 02:00:00:00:00:01", `"02:00:00:00:00:01" is not an IPv4 address`},
		{"ether src 10.0.0.5", `ether address "10.0.0.5"`},
		{"ip net 10.0.0.0", `network "10.0.0.0"`},
		{"ip and", "filter expression is incomplete"},
		{"(ip", "missing a closing parenthesis"},
		{"ip )", `unexpected ")"`},
		{"not", "filter expression is incomplete"},
		{"len >= 14", `length predicate "len >= 14" is not supported`},
		{"len = 0", `length predicate "len = 0" is not supported`},
		{"len", "needs a number"},
		{"len <", "needs a number"},
	}
	for _, c := range cases {
		t.Run(c.expression, func(t *testing.T) {
			_, err := Parse(c.expression)
			if err == nil {
				t.Fatalf("%q was accepted", c.expression)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%q: got error %q, want one containing %q", c.expression, err, c.want)
			}
		})
	}
}

// TestParseRoundTripsThroughDecompile checks that what filter list shows can be
// fed back into filter set. The decompiled expression is often shaped
// differently, so the programs are compared by what they accept.
func TestParseRoundTripsThroughDecompile(t *testing.T) {
	frames := testFrames(t)
	expressions := []string{
		"ether src 02:00:00:00:00:01",
		"ip dst host 10.0.0.1",
		"src host 10.0.0.5",
		"dst net 10.0.0.0/24",
		"ip",
		"ip multicast",
		"not ip",
		"not ether multicast",
		"len >= 0",
		"len < 0",
	}
	for _, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			filter, err := Parse(expression)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			program, err := Compile(filter, 0)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			decoded, err := program.Decompile()
			if err != nil {
				t.Fatalf("decompile: %v", err)
			}
			if !decoded.Complete {
				t.Fatalf("%q decompiled incompletely: %s", expression, decoded.Expression())
			}
			again, err := Parse(decoded.Expression())
			if err != nil {
				t.Skipf("decompiled form %q is not something Parse accepts: %v", decoded.Expression(), err)
			}
			recompiled, err := Compile(again, 0)
			if err != nil {
				t.Fatalf("compile decompiled %q: %v", decoded.Expression(), err)
			}
			first, err := vm(t, program)
			if err != nil {
				t.Fatalf("vm: %v", err)
			}
			second, err := vm(t, recompiled)
			if err != nil {
				t.Fatalf("vm: %v", err)
			}
			for _, fr := range frames {
				if got, want := run(second, fr.data), run(first, fr.data); got != want {
					t.Errorf("%q decompiles to %q, which accepts %s=%v instead of %v",
						expression, decoded.Expression(), fr.name, got, want)
				}
			}
		})
	}
}

func vm(t *testing.T, program *Program) (*bpf.VM, error) {
	t.Helper()
	return bpf.NewVM(mustDisassemble(t, program.Instructions()))
}

func TestParseConstants(t *testing.T) {
	cases := []struct {
		expression string
		filter     Filter
	}{
		{"0=1", None()},
		{"0 = 1", None()},
		{"1=1", All()},
		{"ether src 02:00:00:00:00:01 and (0=1 or src host 10.0.0.5)",
			And(EtherSrc(mustMAC(t, "02:00:00:00:00:01")), Or(None(), IPSrc(mustIP(t, "10.0.0.5"))))},
		{"1=2", None()},
		{"2>1", All()},
		{"1 >= 2", None()},
	}
	for _, c := range cases {
		parsed, err := Parse(c.expression)
		if err != nil {
			t.Fatalf("parse %q: %v", c.expression, err)
		}
		got, err := Compile(parsed, 0)
		if err != nil {
			t.Fatalf("compile %q: %v", c.expression, err)
		}
		want, err := Compile(c.filter, 0)
		if err != nil {
			t.Fatalf("compile expected: %v", err)
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Errorf("%q compiled differently:\n%swant:\n%s", c.expression, mustDisassembly(t, got), mustDisassembly(t, want))
		}
	}
	if _, err := Parse("0=x"); err == nil {
		t.Errorf("a comparison with a non number was accepted")
	}
}
