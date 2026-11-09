package cni

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
)

// fakeIPAM writes an IPAM plugin that answers with the address of the test and
// records the commands it was called with.
func fakeIPAM(t *testing.T, answer string) (dir string, calls func() []string) {
	t.Helper()
	dir = t.TempDir()
	script := `#!/bin/sh
echo "$CNI_COMMAND $CNI_CONTAINERID $CNI_IFNAME" >> "` + dir + `/calls"
` + ipamAddress + `case "$CNI_COMMAND" in
ADD)
	cat > "` + dir + `/conf"
	cat << JSON
` + answer + `
JSON
	;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "host-local"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the fake plugin: %v", err)
	}
	return dir, func() []string {
		data, err := os.ReadFile(filepath.Join(dir, "calls"))
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

const ipamAnswer = `{"cniVersion":"1.0.0","ips":[{"address":"$address/16","gateway":"10.89.0.1"}],"routes":[{"dst":"0.0.0.0/0"}],"dns":{"nameservers":["10.89.0.1"]}}`

// ipamAddress maps a container id to the address the fake plugin hands out, so
// that two containers of a test do not share one.
const ipamAddress = `case "$CNI_CONTAINERID" in
jail1) address=10.89.0.21 ;;
jail2) address=10.89.0.22 ;;
*) address=10.89.0.23 ;;
esac
`

func ipamConfig() *Config {
	conf := testConfig()
	conf.IPAM = types.IPAM{Type: "host-local"}
	conf.IsGateway = true
	return conf
}

func TestAddUsesTheIPAMAddress(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, calls := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	result, err := plugin.Add(ctx, req)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if recorded := calls(); len(recorded) != 1 || recorded[0] != "ADD jail1 eth0" {
		t.Errorf("the IPAM plugin was called with %v", recorded)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "conf")); err != nil {
		t.Errorf("the IPAM plugin got no configuration: %v", err)
	} else if !strings.Contains(string(data), "\"host-local\"") {
		t.Errorf("the IPAM plugin got %q", data)
	}

	state, _, err := loadState(plugin.StateDir, "jailnet", "jail1", "eth0")
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if state.IP != "10.89.0.21/16" {
		t.Errorf("state address %q", state.IP)
	}
	filters, err := plugin.Manager.Filters(ctx, "bridge0", state.Port)
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	expressions := map[string]string{}
	for _, row := range filters {
		expressions[row.Hook] = row.Expression
	}
	if !strings.Contains(expressions["member"], "src host 10.89.0.21") {
		t.Errorf("the incoming filter %q", expressions["member"])
	}
	if !strings.Contains(expressions["bridge"], "ip dst host 10.89.0.21") {
		t.Errorf("the outgoing filter %q", expressions["bridge"])
	}

	if len(result.IPs) != 1 {
		t.Fatalf("result %+v", result)
	}
	if result.IPs[0].Address.String() != "10.89.0.21/16" {
		t.Errorf("result address %q", result.IPs[0].Address.String())
	}
	if result.IPs[0].Interface == nil || *result.IPs[0].Interface != 1 {
		t.Errorf("the address does not point at the container interface: %+v", result.IPs[0])
	}
	if len(result.Routes) != 1 || result.Routes[0].Dst.String() != "0.0.0.0/0" {
		t.Errorf("result routes %+v", result.Routes)
	}
	if len(result.DNS.Nameservers) != 1 {
		t.Errorf("result dns %+v", result.DNS)
	}

	host := sim.Node("bridge0-if")
	if host == nil {
		t.Fatalf("no host interface in %v", sim.Nodes())
	}
	found := false
	for _, address := range host.Addrs {
		if strings.HasPrefix(address, "10.89.0.1/16") {
			found = true
		}
	}
	if !found {
		t.Errorf("the gateway is not on the bridge interface: %v", host.Addrs)
	}
}

func TestAddWithoutIsGatewayLeavesTheBridgeWithoutAnAddress(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, _ := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	conf.IsGateway = false
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	host := sim.Node("bridge0-if")
	if host == nil {
		t.Fatalf("no host interface in %v", sim.Nodes())
	}
	if len(host.Addrs) != 0 {
		t.Errorf("the bridge got an address without isGateway: %v", host.Addrs)
	}
	device := sim.Node("ngeth0")
	if device == nil || len(device.Addrs) != 1 || device.Addrs[0] != "10.89.0.21/16" {
		t.Errorf("the container interface was not configured: %+v", device)
	}
	if routes := sim.Routes("jail1"); len(routes) != 1 || routes[0] != "-4 -net 0.0.0.0/0 10.89.0.1" {
		t.Errorf("the routes of the container: %v", routes)
	}
}

func TestDelReturnsTheAddress(t *testing.T) {
	ctx := context.Background()
	plugin, _ := newTestPlugin(t)
	dir, calls := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := plugin.Del(ctx, req); err != nil {
		t.Fatalf("del: %v", err)
	}
	recorded := calls()
	if len(recorded) != 2 || recorded[0] != "ADD jail1 eth0" || recorded[1] != "DEL jail1 eth0" {
		t.Errorf("the IPAM plugin was called with %v", recorded)
	}
	if err := plugin.Del(ctx, req); err != nil {
		t.Errorf("del without state: %v", err)
	}
	if recorded := calls(); len(recorded) != 3 || recorded[2] != "DEL jail1 eth0" {
		t.Errorf("the address was not given back: %v", recorded)
	}
}

func TestAddReleasesTheAddressOnFailure(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, calls := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	conf.Bridge = "nope"
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	// A node named like the bridge, but of another type, makes the plugin fail
	// after IPAM has handed out an address.
	sim.AddNode("nope", "socket")
	if _, err := plugin.Add(ctx, req); err == nil {
		t.Fatalf("add with a broken bridge succeeded")
	}
	recorded := calls()
	if len(recorded) < 2 || recorded[1] != "DEL jail1 eth0" {
		t.Errorf("the address was not released: %v", recorded)
	}
}

func TestAddWithoutTheIPAMPlugin(t *testing.T) {
	ctx := context.Background()
	plugin, _ := newTestPlugin(t)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = t.TempDir()

	_, err := plugin.Add(ctx, req)
	if err == nil || !strings.Contains(err.Error(), "not found in") {
		t.Fatalf("got %v, want a missing plugin", err)
	}
}

func TestIPAMNotSupported(t *testing.T) {
	for _, message := range []string{
		"plugin: unknown CNI_COMMAND: CHECK",
		"not implemented",
		"version not supported",
	} {
		if !ipamNotSupported(errorString(message)) {
			t.Errorf("%q is not recognised as unsupported", message)
		}
	}
	if ipamNotSupported(errorString("no such file")) {
		t.Errorf("a real failure is treated as unsupported")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func TestCheckAsksIPAM(t *testing.T) {
	ctx := context.Background()
	plugin, _ := newTestPlugin(t)
	dir, calls := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := plugin.Check(ctx, req); err != nil {
		t.Fatalf("check: %v", err)
	}
	recorded := calls()
	if len(recorded) != 2 || recorded[1] != "CHECK jail1 eth0" {
		t.Errorf("check did not reach the IPAM plugin: %v", recorded)
	}
}

func TestAddConfiguresTheJail(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, _ := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	conf.IPMasq = true
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	device := sim.Node("ngeth0")
	if device == nil || len(device.Addrs) != 1 || device.Addrs[0] != "10.89.0.21/16" {
		t.Errorf("the address is not on the interface: %+v", device)
	}
	routes := sim.Routes("jail1")
	if len(routes) != 1 || routes[0] != "-4 -net 0.0.0.0/0 10.89.0.1" {
		t.Errorf("routes %v, want a default route through the gateway", routes)
	}
	if table := sim.Table("cni-nat"); len(table) != 1 || table[0] != "10.89.0.21" {
		t.Errorf("the address is not in the nat table: %v", table)
	}

	if err := plugin.Del(ctx, req); err != nil {
		t.Fatalf("del: %v", err)
	}
	if table := sim.Table("cni-nat"); len(table) != 0 {
		t.Errorf("the address was left in the nat table: %v", table)
	}
}

func TestNatTableIsOptional(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, _ := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	conf.IsGateway = false
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	if table := sim.Table("cni-nat"); len(table) != 0 {
		t.Errorf("a table was touched without ipMasq: %v", table)
	}
	conf.NatTable = "containers"
	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add with a named table: %v", err)
	}
	if table := sim.Table("containers"); len(table) != 1 {
		t.Errorf("the named table is not used: %v", table)
	}
	if table := sim.Table("cni-nat"); len(table) != 0 {
		t.Errorf("the default table is used although one is named: %v", table)
	}
}

func TestForceGateway(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, _ := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	conf.IsForceGateway = true
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	device := sim.Node("ngeth0")
	if device == nil || len(device.Addrs) != 1 || device.Addrs[0] != "10.89.0.21/32" {
		t.Errorf("the address is not a /32: %+v", device)
	}
	want := []string{
		"-4 -host 10.89.0.1 -interface eth0",
		"-4 -net 0.0.0.0/0 10.89.0.1",
	}
	routes := sim.Routes("jail1")
	if len(routes) != len(want) {
		t.Fatalf("routes %v, want %v", routes, want)
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Errorf("route %d %q, want %q", i, routes[i], want[i])
		}
	}
	filters, err := plugin.Manager.Filters(ctx, "bridge0", "101")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	expressions := map[string]string{}
	for _, row := range filters {
		expressions[row.Hook] = row.Expression
	}
	hostMAC := sim.Node("bridge0-if").MAC
	if hostMAC == "" {
		t.Fatalf("the bridge interface has no address in the simulation")
	}
	if !strings.Contains(expressions["member"], "ether dst "+hostMAC) {
		t.Errorf("the incoming filter does not restrict the destination to %s: %q", hostMAC, expressions["member"])
	}
	if !strings.Contains(expressions["member"], "dst host 10.89.0.1") {
		t.Errorf("the incoming filter does not allow the gateway: %q", expressions["member"])
	}
	if !strings.Contains(expressions["bridge"], "ether src "+hostMAC) {
		t.Errorf("the outgoing filter does not pin the source to %s: %q", hostMAC, expressions["bridge"])
	}
}

func TestRestrictMulticast(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	answer := `{"cniVersion":"1.0.0","ips":[{"address":"10.89.0.21/16","gateway":"10.89.0.1"}],
		"routes":[{"dst":"0.0.0.0/0"},{"dst":"224.0.0.0/4"}]}`
	dir, _ := fakeIPAM(t, answer)
	conf := ipamConfig()
	conf.IsRestrictMulticast = true
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	filters, err := plugin.Manager.Filters(ctx, "bridge0", "101")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	expressions := map[string]string{}
	for _, row := range filters {
		expressions[row.Hook] = row.Expression
	}
	if !strings.Contains(expressions["bridge"], "224.0.0.0/4") {
		t.Errorf("the outgoing filter does not name the multicast network: %q", expressions["bridge"])
	}
	if !strings.Contains(expressions["member"], "ff:ff:ff:ff:ff:ff") {
		t.Errorf("the incoming filter does not allow broadcast: %q", expressions["member"])
	}
	if !strings.Contains(expressions["member"], "224.0.0.0/4") {
		t.Errorf("the incoming filter does not name the multicast network: %q", expressions["member"])
	}
	_ = sim
}

func TestForceGatewayReplacesAForeignDefaultRoute(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	dir, calls := fakeIPAM(t, ipamAnswer)
	conf := ipamConfig()
	conf.IsForceGateway = true
	req := request(conf, "jail1", "eth0")
	req.Path = dir

	// A container whose loopback carries a host route of 0.0.0.0/0 starts with
	// a default route over the loopback, which the plugin has to replace.
	if _, err := sim.Run(ctx, "route", "-j", "jail1", "add", "default", "127.0.0.1"); err != nil {
		t.Fatalf("pre-existing route: %v", err)
	}
	if _, err := plugin.Add(ctx, req); err != nil {
		t.Fatalf("add: %v", err)
	}
	routes := sim.Routes("jail1")
	if len(routes) != 2 {
		t.Fatalf("routes %v", routes)
	}
	changed := false
	for _, route := range routes {
		if strings.Contains(route, "127.0.0.1") {
			t.Errorf("the default route over the loopback survived: %v", routes)
		}
		if route == "-4 -net 0.0.0.0/0 10.89.0.1" {
			changed = true
		}
	}
	if !changed {
		t.Errorf("the default route was not replaced: %v", routes)
	}
	found := false
	for _, call := range sim.Calls() {
		if strings.Contains(call, "route -j jail1 change") {
			found = true
		}
	}
	if !found {
		t.Errorf("the existing default route was not changed: %v", sim.Calls())
	}
	_ = calls
}
