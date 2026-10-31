package cni

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

func gcRequest(conf *Config, path string) Request {
	req := request(conf, "", "")
	req.Config = conf
	req.Path = path
	data, _ := json.Marshal(conf)
	req.Raw = data
	return req
}

func attachments(items ...Attachment) *[]Attachment {
	return &items
}

func TestGCRemovesStaleAttachments(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, calls := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	conf.IPMasq = true
	for i, container := range []string{"jail1", "jail2"} {
		req := request(conf, container, "eth"+strconv.Itoa(i))
		req.Path = dir
		if _, err := plugin.Add(ctx, req); err != nil {
			t.Fatalf("add %s: %v", container, err)
		}
	}
	portsBefore, err := plugin.Manager.Ports(ctx, "bridge0")
	if err != nil || len(portsBefore) != 2 {
		t.Fatalf("ports %v, %v", portsBefore, err)
	}
	tableBefore := sim.Table("cni-nat")
	if len(tableBefore) != 2 {
		t.Fatalf("nat table %v", tableBefore)
	}

	conf.ValidAttachments = attachments(Attachment{ContainerID: "jail1", IfName: "eth0"})
	if err := plugin.GC(ctx, gcRequest(conf, dir)); err != nil {
		t.Fatalf("gc: %v", err)
	}

	ports, err := plugin.Manager.Ports(ctx, "bridge0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want the one of jail1: %+v", len(ports), ports)
	}
	if _, exists, _ := loadStates(plugin, "jail2"); exists {
		t.Errorf("the state of jail2 survived")
	}
	if _, exists, _ := loadStates(plugin, "jail1"); !exists {
		t.Errorf("the state of jail1 was removed")
	}
	table := sim.Table("cni-nat")
	if len(table) != 1 {
		t.Errorf("nat table %v, want only the address of jail1", table)
	}
	if sim.Node("ngeth1") != nil {
		t.Errorf("the port node of jail2 survived")
	}
	if sim.Node("ngeth0") == nil {
		t.Errorf("the port node of jail1 was removed")
	}
	recorded := calls()
	if len(recorded) < 3 || !strings.HasPrefix(recorded[len(recorded)-1], "GC") {
		t.Errorf("the IPAM plugin got %v, want a GC", recorded)
	}
}

func TestGCWithoutTheListDoesNothing(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, _ := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = dir
	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	conf.ValidAttachments = nil
	if err := plugin.GC(ctx, gcRequest(conf, dir)); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if ports, err := plugin.Manager.Ports(ctx, "bridge0"); err != nil || len(ports) != 1 {
		t.Errorf("a configuration without the list removed ports: %+v, %v", ports, err)
	}
	if _, exists, _ := loadStates(plugin, "jail1"); !exists {
		t.Errorf("the state was removed")
	}
	_ = sim
}

func TestGCWithAnEmptyListRemovesEverything(t *testing.T) {
	ctx := context.Background()
	plugin, _ := newTestPlugin(t)
	dir, _ := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = dir
	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	conf.ValidAttachments = attachments()
	if err := plugin.GC(ctx, gcRequest(conf, dir)); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if ports, err := plugin.Manager.Ports(ctx, "bridge0"); err != nil || len(ports) != 0 {
		t.Errorf("ports %+v, %v", ports, err)
	}
	if _, exists, _ := loadStates(plugin, "jail1"); exists {
		t.Errorf("the state survived")
	}
	if _, err := os.Stat(statePath(plugin.StateDir, "jailnet", "jail1", "eth0")); !os.IsNotExist(err) {
		t.Errorf("the state file is still there")
	}
}

func TestGCReleasesAddressWithAnOlderIPAMPlugin(t *testing.T) {
	ctx := context.Background()
	plugin, _ := newTestPlugin(t)
	dir, calls := fakeIPAMWithoutGC(t, ipamAnswer)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = dir
	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	conf.ValidAttachments = attachments()
	if err := plugin.GC(ctx, gcRequest(conf, dir)); err != nil {
		t.Fatalf("gc: %v", err)
	}
	recorded := strings.Join(calls(), "\n")
	if !strings.Contains(recorded, "DEL jail1 eth0") {
		t.Errorf("the address was not given back: %v", calls())
	}
}

func TestGCDoesNotFailOnALostPort(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, _ := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = dir
	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "shutdown", "ngeth0:"); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	conf.ValidAttachments = attachments()
	if err := plugin.GC(ctx, gcRequest(conf, dir)); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, exists, _ := loadStates(plugin, "jail1"); exists {
		t.Errorf("the state of the lost port survived")
	}
}

// loadStates reports the state of a container interface, if it is there.
func loadStates(plugin *Plugin, container string) (State, bool, error) {
	return loadState(plugin.StateDir, "jailnet", container, "eth0")
}

// fakeIPAMWithoutGC writes an IPAM plugin that rejects the GC command, the way
// plugins written before the command existed do.
func fakeIPAMWithoutGC(t *testing.T, answer string) (string, func() []string) {
	t.Helper()
	dir, calls := fakeIPAM(t, answer)
	script := `#!/bin/sh
echo "$CNI_COMMAND $CNI_CONTAINERID $CNI_IFNAME" >> "` + dir + `/calls"
` + ipamAddress + `if [ "$CNI_COMMAND" = "GC" ]; then
	echo "unknown CNI_COMMAND: GC" >&2
	exit 4
fi
if [ "$CNI_COMMAND" = "ADD" ]; then
	cat > "` + dir + `/conf"
	cat << JSON
` + answer + `
JSON
fi
exit 0
`
	if err := os.WriteFile(dir+"/host-local", []byte(script), 0o755); err != nil {
		t.Fatalf("write the fake plugin: %v", err)
	}
	return dir, calls
}
