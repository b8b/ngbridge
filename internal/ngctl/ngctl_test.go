package ngctl

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type call struct {
	name string
	args []string
}

type fakeRunner struct {
	calls  []call
	stdin  []string
	out    string
	err    error
	byVerb map[string]string
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.RunInput(ctx, "", name, args...)
}

func (f *fakeRunner) RunInput(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name: name, args: args})
	f.stdin = append(f.stdin, stdin)
	if f.err != nil {
		return nil, f.err
	}
	if f.byVerb != nil && len(args) > 0 {
		return []byte(f.byVerb[args[0]]), nil
	}
	return []byte(f.out), nil
}

const showOutput = "  Name: ngeth0          Type: eiface          ID: 0000000a   Num hooks: 1\n"

func TestMkPeerShowsPeerHookPath(t *testing.T) {
	runner := &fakeRunner{}
	ng := &Ngctl{Path: "ngctl", Runner: runner}

	path, err := ng.MkPeer(context.Background(), "ngeth0:", "bpf", "ether", "jail")
	if err != nil {
		t.Fatalf("mkpeer: %v", err)
	}
	if path != "ngeth0:ether" {
		t.Errorf("peer path %q, want ngeth0:ether", path)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("got %d calls, want 1: %+v", len(runner.calls), runner.calls)
	}
	if got := strings.Join(runner.calls[0].args, " "); got != "mkpeer ngeth0: bpf ether jail" {
		t.Errorf("mkpeer args: %q", got)
	}
}

func TestMkPeerOnRootNode(t *testing.T) {
	runner := &fakeRunner{}
	ng := &Ngctl{Runner: runner}

	path, err := ng.MkPeer(context.Background(), "", "eiface", "ngeth0", "ether")
	if err != nil {
		t.Fatalf("mkpeer: %v", err)
	}
	if path != "" {
		t.Errorf("peer path %q, want empty for a node behind .", path)
	}
	if got := strings.Join(runner.calls[0].args, " "); got != "mkpeer . eiface ngeth0 ether" {
		t.Errorf("mkpeer args: %q", got)
	}
	if len(runner.calls) != 1 {
		t.Errorf("got %d calls, want 1", len(runner.calls))
	}
}

func TestSetProgram(t *testing.T) {
	runner := &fakeRunner{out: "  Args: \n"}
	ng := &Ngctl{Path: "/usr/sbin/ngctl", Runner: runner}

	program := `{ thisHook="jail" ifMatch="bridge" ifNotMatch="" bpf_prog_len=0 bpf_prog=[ ] }`
	if _, err := ng.SetProgram(context.Background(), "bpfngeth0:", program); err != nil {
		t.Fatalf("setprogram: %v", err)
	}
	if runner.calls[0].name != "/usr/sbin/ngctl" {
		t.Errorf("binary %q, want /usr/sbin/ngctl", runner.calls[0].name)
	}
	want := []string{"msg", "bpfngeth0:", "setprogram", program}
	if len(runner.calls[0].args) != len(want) {
		t.Fatalf("got args %q", runner.calls[0].args)
	}
	for i := range want {
		if runner.calls[0].args[i] != want[i] {
			t.Errorf("arg %d: got %q, want %q", i, runner.calls[0].args[i], want[i])
		}
	}
}

func TestConnectArguments(t *testing.T) {
	runner := &fakeRunner{}
	ng := &Ngctl{Runner: runner}
	if err := ng.Connect(context.Background(), "ngeth5:", "ether", "br0:", "link105"); err != nil {
		t.Fatalf("connect: %v", err)
	}
	want := "connect ngeth5: br0: ether link105"
	if got := strings.Join(runner.calls[0].args, " "); got != want {
		t.Errorf("connect args %q, want %q", got, want)
	}
}

func TestCommandsFailOnRunnerError(t *testing.T) {
	boom := errors.New("boom")
	ng := &Ngctl{Runner: &fakeRunner{err: boom}}
	ctx := context.Background()
	for name, err := range map[string]error{
		"mkpeer":   func() error { _, err := ng.MkPeer(ctx, "ngeth0:", "bpf", "ether", "jail"); return err }(),
		"name":     ng.Name(ctx, "bpfngeth0:", "bpf0"),
		"connect":  ng.Connect(ctx, "bpf0:", "bridge", "br0:", "link5"),
		"shutdown": ng.Shutdown(ctx, "bpf0:"),
		"show":     func() error { _, err := ng.Show(ctx, "bpf0:"); return err }(),
		"msg":      func() error { _, err := ng.Msg(ctx, "bpf0:", "getstats"); return err }(),
	} {
		if !errors.Is(err, boom) {
			t.Errorf("%s: got %v, want boom", name, err)
		}
	}
}

const bridgeShow = `  Name: br0              Type: bridge           ID: 0000000a   Num hooks: 2
  Local hook      Peer name       Peer type    Peer ID         Peer hook
  ----------      ---------       ---------    -------         ---------
  link0           ngb0            eiface       0000000b        ether
  link2           ngeth0          eiface       0000000c        ether
`

func TestParseShow(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want Node
	}{
		"named": {showOutput, Node{Name: "ngeth0", Type: "eiface", ID: "0000000a", Hooks: 1}},
		"long name": {
			"  Name: bpfngeth0-with-a-long-name Type: bpf       ID: 0000000b   Num hooks: 2\n",
			Node{Name: "bpfngeth0-with-a-long-name", Type: "bpf", ID: "0000000b", Hooks: 2},
		},
		"unnamed": {
			"  Name: <unnamed>       Type: bpf              ID: 0000000c   Num hooks: 0\n",
			Node{Name: "<unnamed>", Type: "bpf", ID: "0000000c", Hooks: 0},
		},
		"with hooks": {
			bridgeShow,
			Node{
				Name: "br0", Type: "bridge", ID: "0000000a", Hooks: 2,
				Links: []Link{
					{Hook: "link0", PeerName: "ngb0", PeerType: "eiface", PeerID: "0000000b", PeerHook: "ether"},
					{Hook: "link2", PeerName: "ngeth0", PeerType: "eiface", PeerID: "0000000c", PeerHook: "ether"},
				},
			},
		},
	} {
		got, err := ParseShow(tc.out)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, tc.want)
		}
	}
	if _, err := ParseShow("cannot find node"); err == nil {
		t.Error("expected an error for output without node information")
	}
}

func TestParseList(t *testing.T) {
	nodes, err := ParseList(`There are 3 total nodes:
  Name: ngb0             Type: eiface           ID: 0000000b   Num hooks: 1
  Name: br0              Type: bridge           ID: 0000000a   Num hooks: 2
  Name: <unnamed>        Type: socket           ID: 0000000d   Num hooks: 0
`)
	if err != nil {
		t.Fatalf("parse list: %v", err)
	}
	want := []Node{
		{Name: "ngb0", Type: "eiface", ID: "0000000b", Hooks: 1},
		{Name: "br0", Type: "bridge", ID: "0000000a", Hooks: 2},
		{Name: "<unnamed>", Type: "socket", ID: "0000000d", Hooks: 0},
	}
	if !reflect.DeepEqual(nodes, want) {
		t.Errorf("got %+v, want %+v", nodes, want)
	}
	if nodes, err := ParseList("There are 0 total nodes:\n"); err != nil || len(nodes) != 0 {
		t.Errorf("empty list: got %v, %v", nodes, err)
	}
	if _, err := ParseList("ngctl: no such file"); err == nil {
		t.Error("expected an error for output without a node list")
	}
}

func TestParseIfName(t *testing.T) {
	got, err := ParseIfName("Rec'd response \"getifname\" (1) from \"[0000000b]:\":\nArgs:\t\"ngeth0\"\n")
	if err != nil {
		t.Fatalf("parse ifname: %v", err)
	}
	if got != "ngeth0" {
		t.Errorf("got %q, want ngeth0", got)
	}
	if got, err := ParseIfName("Args:\tbr0\n"); err != nil || got != "br0" {
		t.Errorf("unquoted: got %q, %v", got, err)
	}
	if _, err := ParseIfName("No arguments"); err == nil {
		t.Error("expected an error for a reply without arguments")
	}
}

func TestShowReportsMissingNodes(t *testing.T) {
	ng := &Ngctl{Path: "ngctl", Runner: &fakeRunner{
		err: errors.New(`ngctl show nope:: exit status 71: ngctl: no node named "nope"`),
	}}
	if _, err := ng.Show(context.Background(), "nope:"); !errors.Is(err, ErrNoSuchNode) {
		t.Errorf("got %v, want ErrNoSuchNode", err)
	}

	ng = &Ngctl{Path: "ngctl", Runner: &fakeRunner{
		err: errors.New(`ngctl show bridge0:: exit status 71: ngctl: send msg: No such file or directory`),
	}}
	if _, err := ng.Show(context.Background(), "bridge0:"); !errors.Is(err, ErrNoSuchNode) {
		t.Errorf("got %v, want ErrNoSuchNode for a node that does not resolve", err)
	}

	ng = &Ngctl{Path: "ngctl", Runner: &fakeRunner{
		err: errors.New("ngctl show br0:: exit status 1: permission denied"),
	}}
	if _, err := ng.Show(context.Background(), "br0:"); err == nil || errors.Is(err, ErrNoSuchNode) {
		t.Errorf("got %v, want a plain error", err)
	}
}

func TestScriptRunsCommandsInOneProcess(t *testing.T) {
	runner := &fakeRunner{out: showOutput}
	ng := &Ngctl{Path: "ngctl", Runner: runner}

	out, err := ng.Script(context.Background(), "mkpeer . eiface new_eiface ether", "show -n .:new_eiface")
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if !strings.Contains(out, "ngeth0") {
		t.Errorf("script output %q", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("got %d calls, want one: %v", len(runner.calls), runner.calls)
	}
	if got := strings.Join(runner.calls[0].args, " "); got != "-f -" {
		t.Errorf("invoked as %q, want -f -", got)
	}
	want := "mkpeer . eiface new_eiface ether\nshow -n .:new_eiface\n"
	if runner.stdin[0] != want {
		t.Errorf("stdin %q, want %q", runner.stdin[0], want)
	}
}
