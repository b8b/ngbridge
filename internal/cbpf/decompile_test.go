package cbpf

import (
	"fmt"
	"testing"

	"golang.org/x/net/bpf"
)

const getProgramReply = `Rec'd response "getprogram" (2) from "[0000000b]:":
Args:	{ thisHook="jail" ifMatch="bridge" ifNotMatch="debug" bpf_prog_len=8 bpf_prog=[ { code=48 jt=0 jf=0 k=6 } { code=21 jt=0 jf=3 k=33554432 } { code=40 jt=0 jf=0 k=10 } { code=21 jt=0 jf=1 k=1 } { code=5 jt=0 jf=0 k=1 } { code=5 jt=0 jf=0 k=1 } { code=6 jt=0 jf=0 k=262144 } { code=6 jt=0 jf=0 k=0 } ] }
`

func TestParseHookProgram(t *testing.T) {
	hook, err := ParseHookProgram(getProgramReply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hook.ThisHook != "jail" || hook.IfMatch != "bridge" || hook.IfNotMatch != "debug" {
		t.Errorf("unexpected hooks %+v", hook)
	}
	if hook.Program.Len() != 8 {
		t.Fatalf("got %d instructions, want 8", hook.Program.Len())
	}
	first := hook.Program.Instructions()[0]
	if first.Op != 48 || first.K != 6 {
		t.Errorf("unexpected first instruction %+v", first)
	}
}

func TestParseHookProgramRoundTrip(t *testing.T) {
	prog, err := Compile(And(EtherSrc(mustMAC(t, "02:00:00:00:00:01")), IPSrc(mustIP(t, "10.0.0.5"))), 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ascii, err := prog.NGctlProgram("jail", "bridge", "debug")
	if err != nil {
		t.Fatalf("ngctl program: %v", err)
	}
	hook, err := ParseHookProgram("Args:\t" + ascii)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hook.ThisHook != "jail" || hook.IfMatch != "bridge" || hook.IfNotMatch != "debug" {
		t.Errorf("unexpected hooks %+v", hook)
	}
	if got, want := hook.Program.Instructions(), prog.Instructions(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("instructions differ\n got %v\nwant %v", got, want)
	}
}

// realReply is what "ngctl msg bpfngeth3: getprogram jail" printed on a node
// configured by the ng_bpf(4) man page shell example: the kernel prints code in
// hex and omits every structure field that equals its default value.
const realReply = "Rec'd response \"getprogram\" (2) from \"[25]:\":\n" +
	"Args:\t{ thisHook=\"jail\" ifMatch=\"bridge\" ifNotMatch=\"debug\" bpf_prog_len=14 " +
	"bpf_prog=[ { code=0x20 k=8 } { code=0x15 jf=11 k=4228922478 } { code=0x28 k=6 } " +
	"{ code=0x15 jf=9 k=22684 } { code=0x28 k=12 } { code=0x15 jf=2 k=2048 } " +
	"{ code=0x20 k=26 } { code=0x15 jt=4 jf=5 k=173539351 } { code=0x15 jt=1 k=2054 } " +
	"{ code=0x15 jf=3 k=32821 } { code=0x20 k=28 } { code=0x15 jf=1 k=173539351 } " +
	"{ code=0x6 k=8192 } { code=0x6 } ] }\n"

func TestParseHookProgramSparse(t *testing.T) {
	hook, err := ParseHookProgram(realReply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hook.ThisHook != "jail" || hook.IfMatch != "bridge" || hook.IfNotMatch != "debug" {
		t.Errorf("unexpected hooks %+v", hook)
	}
	if hook.Program.Len() != 14 {
		t.Fatalf("got %d instructions, want 14", hook.Program.Len())
	}
	insns := hook.Program.Instructions()
	if insns[0].Op != 0x20 || insns[0].K != 8 {
		t.Errorf("first instruction %+v", insns[0])
	}
	if insns[1].Op != 0x15 || insns[1].Jf != 11 || insns[1].K != 4228922478 {
		t.Errorf("second instruction %+v", insns[1])
	}
	if last := insns[13]; last.Op != 0x6 || last.K != 0 || last.Jt != 0 {
		t.Errorf("last instruction %+v", last)
	}
}

func TestDecompileSparseProgram(t *testing.T) {
	hook, err := ParseHookProgram(realReply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	decoded, err := hook.Program.Decompile()
	if err != nil {
		t.Fatalf("decompile: %v", err)
	}
	if !decoded.Complete {
		t.Errorf("decompilation incomplete")
	}
	want := "(ether src 58:9c:fc:10:3c:6e and arp src host 10.88.0.23) or " +
		"(ether src 58:9c:fc:10:3c:6e and rarp src host 10.88.0.23) or " +
		"(ether src 58:9c:fc:10:3c:6e and ip src host 10.88.0.23)"
	if got := decoded.Expression(); got != want {
		t.Errorf("expression:\n got %s\nwant %s", got, want)
	}
}

func TestParseHookProgramErrors(t *testing.T) {
	for name, reply := range map[string]string{
		"no program":     `Rec'd response "getprogram" (2) from "bpf0:":` + "\nArgs:\t\n",
		"count mismatch": `Args:	{ thisHook="jail" ifMatch="" ifNotMatch="" bpf_prog_len=2 bpf_prog=[ { code=6 jt=0 jf=0 k=262144 } ] }`,
		"garbage":        `ngctl: no such node`,
	} {
		if _, err := ParseHookProgram(reply); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestDecompileExpressions(t *testing.T) {
	jailMAC := mustMAC(t, "02:00:00:00:00:01")
	hostMAC := mustMAC(t, "02:00:00:00:00:02")
	jailIP := mustIP(t, "10.0.0.5")
	hostIP := mustIP(t, "10.0.0.1")
	multicastNet := mustCIDR(t, "224.0.0.0/4")

	for name, tc := range map[string]struct {
		filter Filter
		want   string
	}{
		"all":       {All(), "len >= 0"},
		"mac pair":  {And(EtherSrc(jailMAC), EtherDst(hostMAC)), "ether src 02:00:00:00:00:01 and ether dst 02:00:00:00:00:02"},
		"broadcast": {EtherBroadcast(), "ether dst ff:ff:ff:ff:ff:ff"},
		"multicast": {EtherMulticast(), "ether[0:1] & 0x1 != 0"},
		"no multicast": {
			Not(EtherMulticast()),
			"ether[0:1] & 0x1 = 0",
		},
		"ipv4 src": {IPv4Src(jailIP), "ip src host 10.0.0.5"},
		"ipv4 dst": {IPv4Dst(hostIP), "ip dst host 10.0.0.1"},
		"src host": {
			IPSrc(jailIP),
			"(rarp src host 10.0.0.5) or (arp src host 10.0.0.5) or (ip src host 10.0.0.5)",
		},
		"dst net": {
			IPv4DstNet(multicastNet),
			"(rarp dst net 224.0.0.0/4) or (arp dst net 224.0.0.0/4) or (ip dst net 224.0.0.0/4)",
		},
		"ip multicast": {IPv4Multicast(), "ip dst net 224.0.0.0/4"},
	} {
		prog, err := Compile(tc.filter, 0)
		if err != nil {
			t.Fatalf("%s: compile: %v", name, err)
		}
		decoded, err := prog.Decompile()
		if err != nil {
			t.Fatalf("%s: decompile: %v", name, err)
		}
		if !decoded.Complete {
			t.Errorf("%s: decompilation incomplete", name)
		}
		if got := decoded.Expression(); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, tc.want)
		}
	}
}

func TestDecompileDefaultProgram(t *testing.T) {
	hook, err := ParseHookProgram(`Args:	{ thisHook="jail" bpf_prog_len=1 bpf_prog=[ { code=0x6 } ] }`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hook.IfMatch != "" || hook.IfNotMatch != "" {
		t.Errorf("unexpected hooks %+v", hook)
	}
	decoded, err := hook.Program.Decompile()
	if err != nil {
		t.Fatalf("decompile: %v", err)
	}
	if len(decoded.Clauses) != 0 {
		t.Errorf("got clauses %q, want none", decoded.Clauses)
	}
	if got := decoded.Expression(); got != "len < 0" {
		t.Errorf("expression %q, want len < 0", got)
	}
}

func TestDecompileOfTcpdumpProgram(t *testing.T) {
	theirs := libpcapProgram(t, tcpdumpPath(t), "ip and tcp")
	prog := &Program{insns: theirs}
	decoded, err := prog.Decompile()
	if err != nil {
		t.Fatalf("decompile: %v", err)
	}
	if got := decoded.Expression(); got != "ip and ether[23:1] = 0x6" {
		t.Errorf("got %s", got)
	}
}

// TestDecompileRoundTrip checks that the decompiled expression selects the same
// frames as the original program did.
func TestDecompileRoundTrip(t *testing.T) {
	tcpdump := tcpdumpPath(t)
	frames := testFrames(t)
	for _, pf := range pcapFilters(t) {
		t.Run(pf.name, func(t *testing.T) {
			ours, err := Compile(pf.filter, 0)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			decoded, err := ours.Decompile()
			if err != nil {
				t.Fatalf("decompile: %v", err)
			}
			if !decoded.Complete {
				t.Fatalf("decompilation incomplete: %s", decoded.Expression())
			}
			expression := decoded.Expression()
			recompiled := libpcapProgram(t, tcpdump, expression)
			theirVM, err := bpf.NewVM(mustDisassemble(t, recompiled))
			if err != nil {
				t.Fatalf("recompiled %q: %v", expression, err)
			}
			ourVM, err := bpf.NewVM(mustDisassemble(t, ours.Instructions()))
			if err != nil {
				t.Fatalf("our vm: %v", err)
			}
			for _, fr := range frames {
				if got, want := run(ourVM, fr.data), run(theirVM, fr.data); got != want {
					t.Errorf("%q: program says %v, decompiled %q says %v", fr.name, got, expression, want)
				}
			}
		})
	}
}
