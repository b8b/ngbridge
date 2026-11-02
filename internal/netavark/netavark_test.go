package netavark

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
	"github.com/b8b/libjail/ngbridge/internal/ngsim"
)

func newTestPlugin(t *testing.T) (*plugin, *ngsim.Netgraph) {
	t.Helper()
	sim := ngsim.New()
	manager := &bridge.Manager{Ng: &ngctl.Ngctl{Runner: sim}, Ifconfig: "ifconfig"}
	return newPlugin(manager, t.TempDir()), sim
}

// testRequest is what podman sends for one container on the default network.
func testRequest() *request {
	return &request{
		ContainerID: "c0ffee",
		Networks: map[string]perNetworkOptions{
			"podman": {
				StaticIPs:     []string{"10.88.0.2"},
				StaticMAC:     "02:11:22:33:44:55",
				InterfaceName: "eth0",
			},
		},
		NetworkInfo: map[string]network{
			"podman": {
				Driver:           "bridge",
				NetworkInterface: "podman0",
				Subnets:          []subnet{{Subnet: "10.88.0.0/16", Gateway: "10.88.0.1"}},
			},
		},
	}
}

// nodeByIface reports the simulated interface named ifname in jail, with an
// empty jail for the network stack of the host.
func nodeByIface(sim *ngsim.Netgraph, ifname, jail string) *ngsim.Node {
	for _, node := range sim.Nodes() {
		if node.Ifname == ifname && node.Jail == jail {
			return node
		}
	}
	return nil
}

// jailInterfaces reports the interfaces of a simulated jail, without its
// loopback, which is not something this command creates.
func jailInterfaces(sim *ngsim.Netgraph, jail string) []*ngsim.Node {
	interfaces := []*ngsim.Node{}
	for _, node := range sim.Nodes() {
		if node.Jail == jail && node.Ifname != "lo0" {
			interfaces = append(interfaces, node)
		}
	}
	return interfaces
}

func TestSetupCreatesBridgePortAndAddresses(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)

	status, err := plugin.setup(ctx, testRequest(), "jail1")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	block, ok := status["podman"]
	if !ok {
		t.Fatalf("no status for the network: %+v", status)
	}
	iface, ok := block.Interfaces["eth0"]
	if !ok {
		t.Fatalf("no interface in the status: %+v", block)
	}
	if iface.MacAddress != "02:11:22:33:44:55" {
		t.Errorf("mac %q", iface.MacAddress)
	}
	want := []netAddress{{IPNet: "10.88.0.2/16", Gateway: "10.88.0.1"}}
	if !slices.Equal(iface.Subnets, want) {
		t.Errorf("addresses %+v, want %+v", iface.Subnets, want)
	}

	if node := sim.Node("podman0"); node == nil || node.Type != "bridge" {
		t.Fatalf("the bridge was not created: %+v", sim.Nodes())
	}
	host := nodeByIface(sim, "podman0", "")
	if host == nil {
		t.Fatalf("the bridge has no host interface: %+v", sim.Nodes())
	}
	if !slices.Contains(host.Addrs, "10.88.0.1/16") {
		t.Errorf("bridge addresses %v, want the gateway", host.Addrs)
	}

	container := nodeByIface(sim, "eth0", "jail1")
	if container == nil {
		t.Fatalf("the interface was not moved into the jail: %+v", sim.Nodes())
	}
	if container.MAC != "02:11:22:33:44:55" {
		t.Errorf("container mac %q", container.MAC)
	}
	if !slices.Contains(container.Addrs, "10.88.0.2/16") {
		t.Errorf("container addresses %v", container.Addrs)
	}

	if routes := sim.Routes("jail1"); !slices.Contains(routes, "-4 default 10.88.0.1") {
		t.Errorf("routes %v, want a default route over the gateway", routes)
	}
	loopback := nodeByIface(sim, "lo0", "jail1")
	if loopback == nil || !slices.Contains(loopback.Addrs, "127.0.0.1/8") {
		t.Errorf("the jail has no loopback address: %+v", loopback)
	}
	if routes := sim.Routes(""); !slices.Contains(routes, "-host 10.88.0.2 -interface podman0") {
		t.Errorf("host routes %v, want a route to the container over the bridge", routes)
	}

	state, exists, err := loadState(plugin.configDir, "podman", "c0ffee")
	if err != nil || !exists {
		t.Fatalf("state %+v, %v", state, err)
	}
	if state.Port != "101" || state.Bridge != "podman0" || state.IfName != "eth0" {
		t.Errorf("unexpected state %+v", state)
	}
	if !slices.Equal(state.Addresses, want) {
		t.Errorf("state addresses %+v, want %+v", state.Addresses, want)
	}
}

func TestSetupFiltersThePort(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)

	if _, err := plugin.setup(ctx, testRequest(), "jail1"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	host := nodeByIface(sim, "podman0", "")
	if host == nil {
		t.Fatalf("the bridge has no host interface: %+v", sim.Nodes())
	}
	hooks, err := plugin.manager.Filters(ctx, "podman0", "101")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	byHook := map[string]string{}
	for _, hook := range hooks {
		byHook[hook.Hook] = hook.Expression
	}
	in := byHook[bridge.FilterMemberHook]
	if !strings.Contains(in, "ether src 02:11:22:33:44:55") || !strings.Contains(in, "src host 10.88.0.2") {
		t.Errorf("the incoming filter does not pin the container: %q", in)
	}
	out := byHook[bridge.FilterBridgeHook]
	if !strings.Contains(out, "ether src "+host.MAC) {
		t.Errorf("the outgoing filter does not pin the bridge: %q", out)
	}
	if !strings.Contains(out, "dst host 10.88.0.2") || !strings.Contains(out, "224.0.0.0/4") {
		t.Errorf("the outgoing filter does not allow the container address and multicast: %q", out)
	}
}

func TestTeardownRemovesFilters(t *testing.T) {
	ctx := context.Background()
	plugin, _ := newTestPlugin(t)
	req := testRequest()

	if _, err := plugin.setup(ctx, req, "jail1"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := plugin.teardown(ctx, req, "jail1"); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if hooks, err := plugin.manager.Filters(ctx, "podman0", "101"); err == nil && len(hooks) != 0 {
		t.Errorf("the teardown left the filters %+v", hooks)
	}
}

func TestSetupDerivesMAC(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	req := testRequest()
	options := req.Networks["podman"]
	options.StaticMAC = ""
	req.Networks["podman"] = options

	status, err := plugin.setup(ctx, req, "jail1")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	mac := derivedMAC("podman", "c0ffee")
	if got := status["podman"].Interfaces["eth0"].MacAddress; got != mac {
		t.Errorf("mac %q, want %q", got, mac)
	}
	if node := nodeByIface(sim, "eth0", "jail1"); node == nil || node.MAC != mac {
		t.Errorf("the interface did not get the derived address: %+v", node)
	}
}

func TestSetupUsesInterfaceNameAndMTU(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	req := testRequest()
	options := req.Networks["podman"]
	options.InterfaceName = "net0"
	req.Networks["podman"] = options
	network := req.NetworkInfo["podman"]
	network.Options = map[string]string{"mtu": "1400"}
	req.NetworkInfo["podman"] = network

	status, err := plugin.setup(ctx, req, "jail1")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, ok := status["podman"].Interfaces["net0"]; !ok {
		t.Errorf("the status does not name net0: %+v", status)
	}
	node := nodeByIface(sim, "net0", "jail1")
	if node == nil {
		t.Fatalf("the interface is not named net0 in the jail: %+v", sim.Nodes())
	}
	if node.MTU != 1400 {
		t.Errorf("mtu %d, want 1400", node.MTU)
	}
}

func TestSetupAddsAddressesToNatTable(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	req := testRequest()
	network := req.NetworkInfo["podman"]
	network.Options = map[string]string{"nat_table": "cni-nat"}
	req.NetworkInfo["podman"] = network

	if _, err := plugin.setup(ctx, req, "jail1"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if table := sim.Table("cni-nat"); !slices.Equal(table, []string{"10.88.0.2"}) {
		t.Errorf("table %v, want the container address", table)
	}

	if err := plugin.teardown(ctx, req, "jail1"); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if table := sim.Table("cni-nat"); len(table) != 0 {
		t.Errorf("table %v, want it empty after the teardown", table)
	}
}

func TestSetupMasqueradesByDefault(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)

	if _, err := plugin.setup(ctx, testRequest(), "jail1"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if table := sim.Table("cni-nat"); !slices.Equal(table, []string{"10.88.0.2"}) {
		t.Errorf("table %v, want the container address", table)
	}
	if err := plugin.teardown(ctx, testRequest(), "jail1"); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if table := sim.Table("cni-nat"); len(table) != 0 {
		t.Errorf("table %v, want it empty after the teardown", table)
	}
}

func TestSetupDoesNotMasquerade(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name  string
		build func(*network)
	}{
		{
			name:  "internal_network",
			build: func(n *network) { n.Internal = true },
		},
		{
			name:  "no_table_named",
			build: func(n *network) { n.Options = map[string]string{"nat_table": ""} },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plugin, sim := newTestPlugin(t)
			req := testRequest()
			withNetwork(req, test.build)
			if _, err := plugin.setup(ctx, req, "jail1"); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if table := sim.Table("cni-nat"); len(table) != 0 {
				t.Errorf("table %v, want it empty", table)
			}
			if state, _, err := loadState(plugin.configDir, "podman", "c0ffee"); err != nil || state.NatTable != "" {
				t.Errorf("state %+v, %v", state, err)
			}
		})
	}
}

func TestSetupAddsRoutesOfTheNetwork(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	req := testRequest()
	network := req.NetworkInfo["podman"]
	network.Routes = []route{{Destination: "10.89.0.0/16", Gateway: "10.88.0.1"}}
	req.NetworkInfo["podman"] = network

	if _, err := plugin.setup(ctx, req, "jail1"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	routes := sim.Routes("jail1")
	for _, want := range []string{"-4 default 10.88.0.1", "-4 -net 10.89.0.0/16 10.88.0.1"} {
		if !slices.Contains(routes, want) {
			t.Errorf("routes %v, want %q", routes, want)
		}
	}
}

func TestSetupReplacesStalePort(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)

	if _, err := plugin.setup(ctx, testRequest(), "jail1"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	req := testRequest()
	options := req.Networks["podman"]
	options.StaticIPs = []string{"10.88.0.7"}
	req.Networks["podman"] = options
	status, err := plugin.setup(ctx, req, "jail1")
	if err != nil {
		t.Fatalf("second setup: %v", err)
	}
	if got := status["podman"].Interfaces["eth0"].Subnets[0].IPNet; got != "10.88.0.7/16" {
		t.Errorf("address %q, want the one of the second setup", got)
	}
	ports, err := plugin.manager.Ports(ctx, "podman0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 {
		t.Errorf("the bridge has %d ports, want one", len(ports))
	}
	if node := nodeByIface(sim, "eth0", "jail1"); node == nil || !slices.Contains(node.Addrs, "10.88.0.7/16") {
		t.Errorf("the stale address is still there: %+v", node)
	}
}

func TestTeardownRemovesPortAndState(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	req := testRequest()

	if _, err := plugin.setup(ctx, req, "jail1"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := plugin.teardown(ctx, req, "jail1"); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if routes := sim.Routes(""); len(routes) != 0 {
		t.Errorf("the teardown left the host routes %v", routes)
	}
	if interfaces := jailInterfaces(sim, "jail1"); len(interfaces) != 0 {
		t.Errorf("the jail still has %+v", interfaces)
	}
	if _, exists, err := loadState(plugin.configDir, "podman", "c0ffee"); err != nil || exists {
		t.Errorf("the state was not removed: %v", err)
	}
	if err := plugin.teardown(ctx, req, "jail1"); err != nil {
		t.Errorf("a repeated teardown failed: %v", err)
	}
}

func TestSetupRollsBackOnFailure(t *testing.T) {
	ctx := context.Background()
	plugin, sim := newTestPlugin(t)
	req := testRequest()
	req.Networks["second"] = perNetworkOptions{StaticIPs: []string{"10.89.0.2"}, InterfaceName: "eth1"}
	req.NetworkInfo["second"] = network{
		Driver:           "macvlan",
		NetworkInterface: "podman1",
		Subnets:          []subnet{{Subnet: "10.89.0.0/16", Gateway: "10.89.0.1"}},
	}

	if _, err := plugin.setup(ctx, req, "jail1"); err == nil {
		t.Fatal("setup succeeded with a driver that is not implemented")
	}
	if interfaces := jailInterfaces(sim, "jail1"); len(interfaces) != 0 {
		t.Errorf("the failed setup left %+v behind", interfaces)
	}
	if _, exists, err := loadState(plugin.configDir, "podman", "c0ffee"); err != nil || exists {
		t.Errorf("the failed setup left state behind: %v", err)
	}
}

func TestSetupRejectsRequests(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name  string
		build func(*request)
	}{
		{
			name:  "no_network",
			build: func(req *request) { req.Networks = map[string]perNetworkOptions{} },
		},
		{
			name:  "no_definition",
			build: func(req *request) { req.NetworkInfo = map[string]network{} },
		},
		{
			name:  "no_bridge_interface",
			build: func(req *request) { withNetwork(req, func(n *network) { n.NetworkInterface = "" }) },
		},
		{
			name:  "IPv6_address",
			build: func(req *request) { withOptions(req, func(o *perNetworkOptions) { o.StaticIPs = []string{"fd00::2"} }) },
		},
		{
			name: "address_outside_the_subnets",
			build: func(req *request) {
				withOptions(req, func(o *perNetworkOptions) { o.StaticIPs = []string{"10.90.0.2"} })
			},
		},
		{
			name:  "no_address",
			build: func(req *request) { withOptions(req, func(o *perNetworkOptions) { o.StaticIPs = nil }) },
		},
		{
			name:  "bad_mtu",
			build: func(req *request) { withNetwork(req, func(n *network) { n.Options = map[string]string{"mtu": "big"} }) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plugin, _ := newTestPlugin(t)
			req := testRequest()
			test.build(req)
			if _, err := plugin.setup(ctx, req, "jail1"); err == nil {
				t.Error("setup succeeded")
			}
		})
	}
}

// withOptions changes the options of one network hands to the container.
func withOptions(req *request, change func(*perNetworkOptions)) {
	options := req.Networks["podman"]
	change(&options)
	req.Networks["podman"] = options
}

// withNetwork changes the definition of the network.
func withNetwork(req *request, change func(*network)) {
	network := req.NetworkInfo["podman"]
	change(&network)
	req.NetworkInfo["podman"] = network
}

// requestJSONMap and requestJSONList are the same request in the two forms
// podman sends: a map keyed by network name up to 5.x, a list of named options
// after that.
const (
	requestJSONMap = `{"container_id":"c0ffee",` +
		`"networks":{"podman":{"static_ips":["10.88.0.2"],"static_mac":"02:11:22:33:44:55","interface_name":"eth0"}},` +
		`"network_info":{"podman":{"driver":"bridge","network_interface":"podman0",` +
		`"subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]}}}`
	requestJSONList = `{"container_id":"c0ffee",` +
		`"networks":[{"name":"podman","static_ips":["10.88.0.2"],"static_mac":"02:11:22:33:44:55","interface_name":"eth0"}],` +
		`"network_info":{"podman":{"driver":"bridge","network_interface":"podman0",` +
		`"subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]}}}`
)

func TestRequestAcceptsBothNetworkForms(t *testing.T) {
	fromMap, fromList := &request{}, &request{}
	if err := json.Unmarshal([]byte(requestJSONMap), fromMap); err != nil {
		t.Fatalf("map form: %v", err)
	}
	if err := json.Unmarshal([]byte(requestJSONList), fromList); err != nil {
		t.Fatalf("list form: %v", err)
	}
	if !reflect.DeepEqual(fromMap, fromList) {
		t.Errorf("the two forms differ:\nmap  %+v\nlist %+v", fromMap, fromList)
	}
	if fromList.Networks["podman"].InterfaceName != "eth0" {
		t.Errorf("interface name %q", fromList.Networks["podman"].InterfaceName)
	}

	unnamed := &request{}
	if err := json.Unmarshal([]byte(`{"networks":[{"static_ips":["10.88.0.2"]}]}`), unnamed); err == nil {
		t.Error("a network of the list without a name was accepted")
	}
}
