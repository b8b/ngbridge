package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
	"github.com/b8b/libjail/ngbridge/internal/cbpf"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
	"github.com/b8b/libjail/ngbridge/internal/ngsim"
)

func newTestPlugin(t *testing.T) (*Plugin, *ngsim.Netgraph) {
	t.Helper()
	sim := ngsim.New()
	manager := &bridge.Manager{Ng: &ngctl.Ngctl{Runner: sim}, Ifconfig: "ifconfig"}
	return &Plugin{Manager: manager, StateDir: t.TempDir()}, sim
}

// request is one plugin invocation for a container interface, without IPAM.
func request(conf *Config, container, ifName string) Request {
	raw, _ := json.Marshal(conf)
	return Request{Config: conf, ContainerID: container, IfName: ifName, Raw: raw}
}

func testConfig() *Config {
	return &Config{
		NetConf: types.NetConf{Name: "jailnet", CNIVersion: "1.0.0"},
		Bridge:  "bridge0",
	}
}

func TestAddCreatesBridgePortAndFilter(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	conf := testConfig()

	result, err := plugin.Add(ctx, request(conf, "jail1", "eth0"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if node := sim.Node("bridge0"); node == nil || node.Type != "bridge" {
		t.Fatalf("the bridge was not created: %v", sim.Nodes())
	}
	ports, err := plugin.Manager.Ports(ctx, "bridge0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 || ports[0].Number() != "101" {
		t.Fatalf("ports %+v", ports)
	}
	if ports[0].Name != "ngeth0" {
		t.Errorf("port device %q, want ngeth0", ports[0].Name)
	}

	state, exists, err := loadState(plugin.StateDir, "jailnet", "jail1", "eth0")
	if err != nil || !exists {
		t.Fatalf("state %+v, %v", state, err)
	}
	mac, err := deriveMAC("jailnet", "jail1")
	if err != nil {
		t.Fatalf("derive mac: %v", err)
	}
	if state.Port != "101" || state.Device != "ngeth0" || state.Bridge != "bridge0" {
		t.Errorf("unexpected state %+v", state)
	}
	if state.MAC != mac {
		t.Errorf("mac %q, want %q", state.MAC, mac)
	}
	if device := sim.Node("ngeth0"); device == nil || device.MAC != mac {
		t.Errorf("the interface address was not set: %+v", device)
	}

	filters, err := plugin.Manager.Filters(ctx, "bridge0", "101")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	byHook := map[string]string{}
	for _, row := range filters {
		byHook[row.Hook] = row.Expression
	}
	if !strings.Contains(byHook[bridge.FilterMemberHook], "ether src "+mac) {
		t.Errorf("the incoming filter does not pin the mac: %+v", filters)
	}
	if strings.Contains(byHook[bridge.FilterMemberHook], "src host") {
		t.Errorf("the incoming filter pins an address the plugin does not know yet: %+v", byHook)
	}
	hostMAC := sim.Node("bridge0-if").MAC
	if !strings.Contains(byHook[bridge.FilterBridgeHook], "ether src "+hostMAC) ||
		!strings.Contains(byHook[bridge.FilterBridgeHook], mac) {
		t.Errorf("the outgoing filter does not pin both addresses: %q", byHook[bridge.FilterBridgeHook])
	}

	device := sim.Node("ngeth0")
	if device.Jail != "jail1" {
		t.Errorf("the interface was not moved into the jail: %+v", device)
	}
	if device.Ifname != "eth0" {
		t.Errorf("interface name %q, want eth0", device.Ifname)
	}
	if device.MTU != 1500 {
		t.Errorf("interface mtu %d, want the mtu of the bridge", device.MTU)
	}
	if len(result.Interfaces) != 2 {
		t.Fatalf("unexpected result %+v", result.Interfaces)
	}
	if host := result.Interfaces[0]; host.Name != "bridge0" || host.Sandbox != "" {
		t.Errorf("the bridge interface is not the first one: %+v", host)
	}
	if container := result.Interfaces[1]; container.Name != "eth0" || container.Mac != mac || container.Sandbox != "jail1" {
		t.Errorf("the container interface is not the second one: %+v", container)
	}
}

func TestAddSecondPassFiltersTheAddress(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	conf := testConfig()

	if _, err := plugin.Add(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("add: %v", err)
	}
	ports, err := plugin.Manager.Ports(ctx, "bridge0")
	if err != nil || len(ports) != 1 {
		t.Fatalf("ports %+v, %v", ports, err)
	}
	// IPAM assigns the address inside the jail.
	if _, err := sim.Run(ctx, "ifconfig", "-j", "jail1", "eth0", "inet", "10.88.0.23/24"); err != nil {
		t.Fatalf("address: %v", err)
	}
	result, err := plugin.Add(ctx, request(conf, "jail1", "eth0"))
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(result.IPs) != 1 || result.IPs[0].Address.IP.String() != "10.88.0.23" ||
		result.IPs[0].Address.Mask.String() != "ffffff00" {
		t.Errorf("unexpected result %+v", result.IPs)
	}
	state, _, err := loadState(plugin.StateDir, "jailnet", "jail1", "eth0")
	if err != nil || state.IP != "10.88.0.23/24" || state.Port != "101" {
		t.Fatalf("state %+v, %v", state, err)
	}
	if ports, err := plugin.Manager.Ports(ctx, "bridge0"); err != nil || len(ports) != 1 {
		t.Fatalf("the second pass created a port: %+v, %v", ports, err)
	}
	filters, err := plugin.Manager.Filters(ctx, "bridge0", "101")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	byHook := map[string]string{}
	for _, row := range filters {
		byHook[row.Hook] = row.Expression
	}
	if !strings.Contains(byHook[bridge.FilterMemberHook], "src host 10.88.0.23") {
		t.Errorf("the incoming filter does not pin the address: %+v", byHook)
	}
	if !strings.Contains(byHook[bridge.FilterBridgeHook], "ip dst host 10.88.0.23") ||
		strings.Contains(byHook[bridge.FilterBridgeHook], "len >= 0") {
		t.Errorf("the outgoing filter %q", byHook[bridge.FilterBridgeHook])
	}
}

func TestAddRoutesTheAddressOverTheBridge(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	conf := testConfig()

	if _, err := plugin.Add(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("add: %v", err)
	}
	// IPAM assigns the address inside the jail, which is the second pass.
	if _, err := sim.Run(ctx, "ifconfig", "-j", "jail1", "eth0", "inet", "10.88.0.23/24"); err != nil {
		t.Fatalf("address: %v", err)
	}
	if _, err := plugin.Add(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("second add: %v", err)
	}
	want := "-host 10.88.0.23 -interface bridge0"
	if routes := sim.Routes(""); len(routes) != 1 || routes[0] != want {
		t.Errorf("host routes %v, want %q", routes, want)
	}
	// A third pass finds the route already there and must not fail.
	if _, err := plugin.Add(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("third add: %v", err)
	}
	if err := plugin.Del(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("del: %v", err)
	}
	if routes := sim.Routes(""); len(routes) != 0 {
		t.Errorf("the host route was not removed: %v", routes)
	}
}

func TestAddIsIdempotentAndSharesTheBridge(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	conf := testConfig()

	first, err := plugin.Add(ctx, request(conf, "jail1", "eth0"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	again, err := plugin.Add(ctx, request(conf, "jail1", "eth0"))
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(again.Interfaces) != 2 || again.Interfaces[1].Mac != first.Interfaces[1].Mac {
		t.Errorf("the second add changed the result: %+v against %+v", again, first)
	}
	if ports, err := plugin.Manager.Ports(ctx, "bridge0"); err != nil || len(ports) != 1 {
		t.Fatalf("ports %+v, %v", ports, err)
	}

	second, err := plugin.Add(ctx, request(conf, "jail2", "eth0"))
	if err != nil {
		t.Fatalf("add for a second container: %v", err)
	}
	if second.Interfaces[1].Mac == first.Interfaces[1].Mac {
		t.Errorf("two containers got the same mac")
	}
	ports, err := plugin.Manager.Ports(ctx, "bridge0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("ports %+v", ports)
	}
	if len(sim.Nodes()) == 0 {
		t.Errorf("the simulation is empty")
	}
}

func TestDelRemovesPortAndState(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	conf := testConfig()

	if _, err := plugin.Add(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := plugin.Del(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("del: %v", err)
	}
	if ports, err := plugin.Manager.Ports(ctx, "bridge0"); err != nil || len(ports) != 0 {
		t.Fatalf("ports %+v, %v", ports, err)
	}
	if sim.Node("ngeth0") != nil {
		t.Errorf("the port node survived")
	}
	if _, exists, err := loadState(plugin.StateDir, "jailnet", "jail1", "eth0"); err != nil || exists {
		t.Errorf("the state survived: %+v, %v", exists, err)
	}
	if err := plugin.Del(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Errorf("a second del failed: %v", err)
	}
}

func TestDelWithoutStateAndWithALostPort(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	conf := testConfig()

	if err := plugin.Del(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Errorf("del without state: %v", err)
	}
	if _, err := plugin.Add(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Somebody removes the port behind the plugin's back.
	if _, err := sim.Run(ctx, "ngctl", "shutdown", "ngeth0:"); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := plugin.Del(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Errorf("del of a lost port: %v", err)
	}
	if _, exists, _ := loadState(plugin.StateDir, "jailnet", "jail1", "eth0"); exists {
		t.Errorf("the state survived")
	}
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	conf := testConfig()

	if err := plugin.Check(ctx, request(conf, "jail1", "eth0")); err == nil {
		t.Errorf("check without state succeeded")
	}
	if _, err := plugin.Add(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := plugin.Check(ctx, request(conf, "jail1", "eth0")); err != nil {
		t.Errorf("check: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "shutdown", "ngeth0:"); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := plugin.Check(ctx, request(conf, "jail1", "eth0")); err == nil {
		t.Errorf("check after the port was removed succeeded")
	}
}

func TestDeriveMACIsStableAndLocal(t *testing.T) {
	first, err := deriveMAC("jailnet", "jail1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	again, err := deriveMAC("jailnet", "jail1")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if first != again {
		t.Errorf("the mac is not stable: %q against %q", first, again)
	}
	other, err := deriveMAC("jailnet", "jail2")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if first == other {
		t.Errorf("two containers share the mac %q", first)
	}
	if !strings.HasPrefix(first, "02:") {
		t.Errorf("mac %q is not locally administered", first)
	}
	if different, _ := deriveMAC("other", "jail1"); different == first {
		t.Errorf("the network name does not take part in the mac")
	}
}

func TestExpressions(t *testing.T) {
	const jailMAC = "02:00:00:00:00:05"
	const hostMAC = "02:00:00:00:00:01"
	conf := testConfig()
	jail := []addressInfo{{Address: "10.89.0.21", Gateway: "10.89.0.1"}}

	cases := []struct {
		name string
		conf *Config
		addr []addressInfo
		join []string
		in   string
		out  string
	}{
		{
			name: "only mac, nothing known yet",
			conf: conf,
			in:   "ether src " + jailMAC + " and ether dst " + hostMAC,
			out:  "ether src " + hostMAC + " and ether dst " + jailMAC,
		},
		{
			name: "address",
			conf: conf,
			addr: jail,
			in:   "ether src " + jailMAC + " and src host 10.89.0.21",
			out:  "(ether src " + hostMAC + " or dst host 10.89.0.21 or ip multicast)",
		},
		{
			name: "force gateway",
			conf: &Config{IsForceGateway: true},
			addr: jail,
			in: "ether src " + jailMAC + " and src host 10.89.0.21" +
				" and (ether dst " + hostMAC + " or dst host 10.89.0.1)",
			out: "(ether src " + hostMAC + " or dst host 10.89.0.21 or ip multicast)",
		},
		{
			name: "restricted multicast",
			conf: &Config{IsRestrictMulticast: true},
			addr: jail,
			join: []string{"224.0.0.0/4"},
			in: "ether src " + jailMAC + " and src host 10.89.0.21" +
				" and (ether broadcast or not ether multicast or dst net 224.0.0.0/4)",
			out: "(ether src " + hostMAC + " or dst host 10.89.0.21 or dst net 224.0.0.0/4)",
		},
		{
			name: "without a host mac",
			conf: conf,
			in:   "ether src " + jailMAC,
			out:  "ether dst " + jailMAC,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotIn := c.conf.inExpression(jailMAC, hostMAC, c.addr, c.join)
			if c.in == "ether src "+jailMAC {
				gotIn = c.conf.inExpression(jailMAC, "", c.addr, c.join)
			}
			if gotIn != c.in {
				t.Errorf("in expression\n got %s\nwant %s", gotIn, c.in)
			}
			gotOut := c.conf.outExpression(jailMAC, hostMAC, c.addr, c.join)
			if c.out == "ether dst "+jailMAC {
				gotOut = c.conf.outExpression(jailMAC, "", c.addr, c.join)
			}
			if gotOut != c.out {
				t.Errorf("out expression\n got %s\nwant %s", gotOut, c.out)
			}
			for _, expression := range []string{c.in, c.out} {
				if _, err := cbpf.Parse(expression); err != nil {
					t.Errorf("%q does not compile: %v", expression, err)
				}
			}
		})
	}

	conf.MAC = "not a mac"
	if _, err := conf.macAddress("jail1"); err == nil {
		t.Errorf("an invalid mac was accepted")
	}
	conf.MAC = ""
	if _, err := conf.macAddress("jail1"); err != nil {
		t.Errorf("mac: %v", err)
	}
	if err := (&Config{}).Validate(); err == nil {
		t.Errorf("a configuration without a name was accepted")
	}
	if got := (&Config{NatTable: "containers"}).natTable(); got != "containers" {
		t.Errorf("nat table %q", got)
	}
	if got := (&Config{IPMasq: true}).natTable(); got != defaultNatTable {
		t.Errorf("nat table %q", got)
	}
	if got := (&Config{}).natTable(); got != "" {
		t.Errorf("nat table %q", got)
	}
}

func TestParseAddress(t *testing.T) {
	status := "eth0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n" +
		"\tether 02:00:00:00:00:05\n" +
		"\tinet 10.88.0.23/24 broadcast 10.88.0.255\n"
	if got := parseAddress(status); got != "10.88.0.23/24" {
		t.Errorf("address %q", got)
	}
	if got := parseAddress("eth0: flags=8863 mtu 1500"); got != "" {
		t.Errorf("address %q, want none", got)
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := State{
		Network: "jail/net", Container: "jail1", IfName: "eth0",
		Bridge: "bridge0", Port: "101", Device: "ngeth0",
		MAC: "02:00:00:00:00:05", MTU: 1500, IP: "10.88.0.23",
	}
	if err := saveState(dir, state); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(statePath(dir, state.Network, state.Container, state.IfName)); err != nil {
		t.Fatalf("state file: %v", err)
	}
	loaded, exists, err := loadState(dir, state.Network, state.Container, state.IfName)
	if err != nil || !exists {
		t.Fatalf("load: %+v, %v", loaded, err)
	}
	if loaded != state {
		t.Errorf("loaded %+v, want %+v", loaded, state)
	}
	if err := removeState(dir, state.Network, state.Container, state.IfName); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, exists, _ := loadState(dir, state.Network, state.Container, state.IfName); exists {
		t.Errorf("the state was not removed")
	}
	if err := removeState(dir, state.Network, state.Container, state.IfName); err != nil {
		t.Errorf("removing a missing state: %v", err)
	}
}

// enoentRunner reports a missing node the way FreeBSD does, which is ENOENT
// instead of the simulation's "no node" message.
type enoentRunner struct {
	*ngsim.Netgraph
}

func (r *enoentRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, "", name, args...)
}

func (r *enoentRunner) RunInput(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	if len(args) > 1 && args[0] == "show" && !strings.HasSuffix(args[1], "]") {
		node := strings.TrimSuffix(args[1], ":")
		if r.Netgraph.Node(node) == nil {
			return nil, fmt.Errorf(`ngctl show %s: exit status 71: ngctl: send msg: No such file or directory`, args[1])
		}
	}
	return r.Netgraph.RunInput(ctx, stdin, name, args...)
}

func TestAddCreatesTheBridgeWhenTheLookupReportsENOENT(t *testing.T) {
	ctx := context.Background()
	sim := ngsim.New()
	manager := &bridge.Manager{Ng: &ngctl.Ngctl{Runner: &enoentRunner{Netgraph: sim}}, Ifconfig: "ifconfig"}
	plugin := &Plugin{Manager: manager, StateDir: t.TempDir()}

	if _, err := plugin.Add(ctx, request(testConfig(), "jail1", "eth0")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if node := sim.Node("bridge0"); node == nil || node.Type != "bridge" {
		t.Fatalf("the bridge was not created: %v", sim.Nodes())
	}
	if err := plugin.Del(ctx, request(testConfig(), "jail1", "eth0")); err != nil {
		t.Fatalf("del: %v", err)
	}
}
