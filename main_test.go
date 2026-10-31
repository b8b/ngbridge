package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/b8b/libjail/ngbridge/internal/ngctl"
	"github.com/b8b/libjail/ngbridge/internal/ngsim"
)

func TestParseAcceptsInterspersedFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	iface := fs.String("iface", "", "interface")
	up := fs.Bool("up", true, "up")
	positional, err := parse(fs, []string{"br0", "--iface", "lan1", "--up=false"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(positional, []string{"br0"}) {
		t.Errorf("positional %q, want [br0]", positional)
	}
	if *iface != "lan1" || *up {
		t.Errorf("flags: iface=%q up=%v", *iface, *up)
	}
}

func TestCommandBridgeAndPort(t *testing.T) {
	sim := ngsim.New()
	ng := &ngctl.Ngctl{Runner: sim}
	ctx := context.Background()

	if err := cmdBridgeCreate(ctx, ng, []string{"br0", "--up=false"}); err != nil {
		t.Fatalf("bridge create: %v", err)
	}
	if err := cmdPortCreate(ctx, ng, []string{"br0"}); err != nil {
		t.Fatalf("port create: %v", err)
	}
	if err := cmdPortCreate(ctx, ng, []string{"br0", "105"}); err != nil {
		t.Fatalf("port create: %v", err)
	}
	if err := cmdPortList(ctx, ng, []string{"br0"}); err != nil {
		t.Fatalf("port list: %v", err)
	}
	if err := cmdPortDestroy(ctx, ng, []string{"br0", "101"}); err != nil {
		t.Fatalf("port destroy: %v", err)
	}
	if node := sim.Node("ngeth0"); node != nil {
		t.Errorf("port node survived")
	}
	if err := cmdBridgeList(ctx, ng, nil); err != nil {
		t.Fatalf("bridge list: %v", err)
	}
	if err := cmdBridgeDestroy(ctx, ng, []string{"br0"}); err != nil {
		t.Fatalf("bridge destroy: %v", err)
	}
	if node := sim.Node("br0"); node != nil {
		t.Errorf("bridge node survived")
	}
}

// captureStdout runs fn with stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = writer
	runErr := fn()
	os.Stdout = saved
	writer.Close()
	out, err := io.ReadAll(reader)
	reader.Close()
	if runErr != nil {
		t.Fatalf("command: %v", runErr)
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(out)
}

func TestJSONOutput(t *testing.T) {
	ctx := context.Background()
	sim := ngsim.New()
	ng := &ngctl.Ngctl{Runner: sim}

	jsonOutput = true
	defer func() { jsonOutput = false }()

	out := captureStdout(t, func() error { return cmdBridgeCreate(ctx, ng, []string{"br0", "--up=false"}) })
	var bridge map[string]any
	if err := json.Unmarshal([]byte(out), &bridge); err != nil {
		t.Fatalf("bridge create is not a JSON object: %v\n%s", err, out)
	}
	for _, field := range []string{"name", "id", "ports", "peer", "peer_id", "interface", "filter", "filter_id"} {
		if _, ok := bridge[field]; !ok {
			t.Errorf("bridge object is missing %q: %s", field, out)
		}
	}

	out = captureStdout(t, func() error { return cmdPortCreate(ctx, ng, []string{"br0"}) })
	var port map[string]any
	if err := json.Unmarshal([]byte(out), &port); err != nil {
		t.Fatalf("port create is not a JSON object: %v\n%s", err, out)
	}
	if port["port"] != "101" || port["bridge"] != "br0" {
		t.Errorf("unexpected port object %v", port)
	}

	out = captureStdout(t, func() error { return cmdPortList(ctx, ng, nil) })
	var ports []map[string]any
	if err := json.Unmarshal([]byte(out), &ports); err != nil {
		t.Fatalf("port list is not a JSON array: %v\n%s", err, out)
	}
	if len(ports) != 1 || ports[0]["peer_id"] != port["peer_id"] {
		t.Errorf("unexpected port list %v", ports)
	}

	out = captureStdout(t, func() error { return cmdBridgeList(ctx, ng, nil) })
	var bridges []map[string]any
	if err := json.Unmarshal([]byte(out), &bridges); err != nil {
		t.Fatalf("bridge list is not a JSON array: %v\n%s", err, out)
	}
	if len(bridges) != 1 || bridges[0]["name"] != "br0" {
		t.Errorf("unexpected bridge list %v", bridges)
	}
}

func TestCommandFilterSet(t *testing.T) {
	ctx := context.Background()
	sim := ngsim.New()
	ng := &ngctl.Ngctl{Runner: sim}

	list := func(bridge, port string) string {
		t.Helper()
		return captureStdout(t, func() error { return cmdFilterList(ctx, ng, []string{bridge, port}) })
	}

	if err := cmdBridgeCreate(ctx, ng, []string{"br0", "--up=false"}); err != nil {
		t.Fatalf("bridge create: %v", err)
	}
	if err := cmdPortCreate(ctx, ng, []string{"br0"}); err != nil {
		t.Fatalf("port create: %v", err)
	}

	set := captureStdout(t, func() error {
		return cmdFilterSet(ctx, ng, []string{"br0", "101",
			"--in", "ether src 02:00:00:00:00:01 and ip src host 10.88.0.23",
			"--out", "ip dst host 10.88.0.23"})
	})
	if node := sim.Node("bpfngeth0"); node == nil {
		t.Fatalf("no filter node in %v", sim.Calls())
	}
	if want := list("br0", "101"); set != want {
		t.Errorf("filter set printed\n%s\nfilter list prints\n%s", set, want)
	}
	for _, want := range []string{"HOOK", "bridge", "member", "debug", "ip dst host 10.88.0.23"} {
		if !strings.Contains(set, want) {
			t.Errorf("filter set is missing %q:\n%s", want, set)
		}
	}

	if err := cmdPortCreate(ctx, ng, []string{"br0"}); err != nil {
		t.Fatalf("second port create: %v", err)
	}
	set = captureStdout(t, func() error {
		return cmdFilterSet(ctx, ng, []string{"br0", "102", "--in", "ip src host 10.88.0.23"})
	})
	if node := sim.Node("bpfngeth1"); node == nil {
		t.Errorf("no filter node for the second port in %v", sim.Calls())
	}
	if want := list("br0", "102"); set != want {
		t.Errorf("filter set printed\n%s\nfilter list prints\n%s", set, want)
	}
	if !strings.Contains(set, "len >= 0") {
		t.Errorf("the direction without a filter is not shown as passing everything:\n%s", set)
	}

	if err := cmdFilterSet(ctx, ng, []string{"br0", "101", "--in", "tcp port 80"}); err == nil ||
		!strings.Contains(err.Error(), `"tcp" is not supported`) {
		t.Errorf("unsupported filter expression: %v", err)
	}
	if err := cmdFilterSet(ctx, ng, []string{"br0"}); err == nil {
		t.Errorf("filter set without a port was accepted")
	}

	nodes := len(sim.Nodes())
	set = captureStdout(t, func() error {
		return cmdFilterSet(ctx, ng, []string{"br0", "101", "--in", "ip src host 10.0.0.9", "--out", "ip dst host 10.0.0.9"})
	})
	if len(sim.Nodes()) != nodes {
		t.Errorf("reconfiguring a filter changed the topology: %v", sim.Nodes())
	}
	if want := list("br0", "101"); set != want {
		t.Errorf("reconfiguring printed\n%s\nfilter list prints\n%s", set, want)
	}
	if strings.Contains(set, "10.88.0.23") {
		t.Errorf("reconfiguration did not replace the programs:\n%s", set)
	}

	out := captureStdout(t, func() error { return cmdFilterDel(ctx, ng, []string{"br0", "101"}) })
	if out != "" {
		t.Errorf("filter del printed %q", out)
	}
	if node := sim.Node("bpfngeth0"); node != nil {
		t.Errorf("the filter node survived")
	}
	if want := list("br0", "101"); strings.Contains(want, "bpfngeth0") {
		t.Errorf("filter list still shows the deleted filter:\n%s", want)
	}
	if err := cmdFilterDel(ctx, ng, []string{"br0", "101"}); err == nil ||
		!strings.Contains(err.Error(), "has no filter") {
		t.Errorf("deleting a missing filter: %v", err)
	}
	if err := cmdFilterDel(ctx, ng, []string{"br0"}); err == nil {
		t.Errorf("filter del without a port was accepted")
	}
	jsonOutput = true
	set = captureStdout(t, func() error {
		return cmdFilterSet(ctx, ng, []string{"br0", "101", "--in", "ip src host 10.0.0.10"})
	})
	jsonOutput = false
	var setRows []map[string]any
	if err := json.Unmarshal([]byte(set), &setRows); err != nil {
		t.Fatalf("filter set is not JSON: %v\n%s", err, set)
	}
	if len(setRows) != 2 || setRows[0]["ifnotmatch"] != "debug" {
		t.Errorf("unexpected filter JSON %v", setRows)
	}
	jsonOutput = true
	listed := captureStdout(t, func() error { return cmdFilterList(ctx, ng, []string{"br0", "101"}) })
	jsonOutput = false
	var listRows []map[string]any
	if err := json.Unmarshal([]byte(listed), &listRows); err != nil {
		t.Fatalf("filter list is not JSON: %v\n%s", err, listed)
	}
	if len(listRows) != len(setRows) {
		t.Errorf("filter set and filter list disagree: %v against %v", setRows, listRows)
	}
	for i := range setRows {
		for field := range setRows[i] {
			if setRows[i][field] != listRows[i][field] {
				t.Errorf("row %d field %q: %v against %v", i, field, setRows[i][field], listRows[i][field])
			}
		}
	}
}

func TestCommandForce(t *testing.T) {
	ctx := context.Background()
	sim := ngsim.New()
	ng := &ngctl.Ngctl{Runner: sim}

	if err := cmdBridgeCreate(ctx, ng, []string{"br0", "--up=false"}); err != nil {
		t.Fatalf("bridge create: %v", err)
	}
	port := "169691"
	if err := cmdPortCreate(ctx, ng, []string{"br0", port}); err != nil {
		t.Fatalf("port create %s: %v", port, err)
	}
	if err := cmdFilterSet(ctx, ng, []string{"br0", port, "--in", "ip src host 10.88.0.5"}); err != nil {
		t.Fatalf("filter set: %v", err)
	}
	if node := sim.Node("bpfngeth0"); node == nil {
		t.Fatalf("no filter node in %v", sim.Calls())
	}
	if err := cmdPortDestroy(ctx, ng, []string{"br0", port}); err != nil {
		t.Fatalf("port destroy: %v", err)
	}
	if node := sim.Node("bpfngeth0"); node != nil {
		t.Errorf("port destroy left the filter behind")
	}
	if node := sim.Node("ngeth0"); node != nil {
		t.Errorf("port destroy left the interface behind")
	}

	if err := cmdPortDestroy(ctx, ng, []string{"br0", port}); err == nil {
		t.Errorf("destroying a missing port without --force succeeded")
	}
	if err := cmdPortDestroy(ctx, ng, []string{"br0", port, "--force"}); err != nil {
		t.Errorf("destroying a missing port with --force: %v", err)
	}
	if err := cmdPortDestroy(ctx, ng, []string{"nope", port, "--force"}); err != nil {
		t.Errorf("destroying a port of a missing bridge with --force: %v", err)
	}
	if err := cmdPortDestroy(ctx, ng, []string{"br0", "abc", "--force"}); err == nil {
		t.Errorf("--force hid a port that is not a number")
	}
	if err := cmdPortDestroy(ctx, ng, []string{"br0", "0", "--force"}); err == nil {
		t.Errorf("--force destroyed the host interface")
	}

	if err := cmdFilterDel(ctx, ng, []string{"br0", "169692"}); err == nil {
		t.Errorf("deleting a filter of a missing port without --force succeeded")
	}
	if err := cmdFilterDel(ctx, ng, []string{"br0", "169692", "--force"}); err != nil {
		t.Errorf("deleting a filter of a missing port with --force: %v", err)
	}
	if err := cmdPortCreate(ctx, ng, []string{"br0", "169693"}); err != nil {
		t.Fatalf("port create: %v", err)
	}
	if err := cmdFilterDel(ctx, ng, []string{"br0", "169693"}); err == nil {
		t.Errorf("deleting a filter from an unfiltered port succeeded")
	}
	if err := cmdFilterDel(ctx, ng, []string{"br0", "169693", "--force"}); err != nil {
		t.Errorf("deleting a filter from an unfiltered port with --force: %v", err)
	}
}
