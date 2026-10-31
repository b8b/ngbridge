package bridge

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/b8b/libjail/ngbridge/internal/cbpf"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
	"github.com/b8b/libjail/ngbridge/internal/ngsim"
)

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("parse mac %q: %v", value, err)
	}
	return mac
}

func mustIP(t *testing.T, value string) net.IP {
	t.Helper()
	ip := net.ParseIP(value)
	if ip == nil {
		t.Fatalf("parse ip %q", value)
	}
	return ip
}

func newTestManager() (*Manager, *ngsim.Netgraph) {
	sim := ngsim.New()
	return &Manager{Ng: &ngctl.Ngctl{Runner: sim}, Ifconfig: "ifconfig"}, sim
}

func TestBridgeLifecycle(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	created, err := manager.Create(ctx, "br0", "", true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Name != "br0" || created.ID != "00000002" || created.Ports != 0 {
		t.Errorf("created %+v", created)
	}
	if created.PeerName != "br0-if" || created.PeerID != "00000001" {
		t.Errorf("peer %q/%q, want br0-if/00000001", created.PeerName, created.PeerID)
	}
	if created.Interface != "br0" || created.Filter != "" || created.FilterID != "" {
		t.Errorf("interface %q filter %q/%q, want br0 and none",
			created.Interface, created.Filter, created.FilterID)
	}
	if node := sim.Node("br0"); node == nil || node.Type != "bridge" {
		t.Fatalf("no bridge node br0 in %v", sim.Nodes())
	}
	host := sim.Node("br0-if")
	if host == nil || host.Type != "eiface" || host.Ifname != "br0" {
		t.Fatalf("unexpected host node %+v", host)
	}
	if !contains(sim.Calls(), "ifconfig ngeth0 name br0") {
		t.Errorf("missing interface rename in %v", sim.Calls())
	}
	if !contains(sim.Calls(), "ifconfig br0 up") {
		t.Errorf("missing interface up in %v", sim.Calls())
	}

	second, err := manager.Create(ctx, "br1", "lan1", false)
	if err != nil {
		t.Fatalf("create second bridge: %v", err)
	}
	if second.Interface != "lan1" {
		t.Errorf("interface %q, want lan1", second.Interface)
	}
	if !contains(sim.Calls(), "ifconfig lan1 up") && contains(sim.Calls(), "ifconfig ngeth1 up") {
		t.Errorf("second interface was brought up without --up")
	}

	bridges, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bridges) != 2 || bridges[0].Name != "br0" || bridges[1].Name != "br1" {
		t.Fatalf("unexpected bridges %+v", bridges)
	}
	if bridges[1].Interface != "lan1" {
		t.Errorf("br1 interface %q, want lan1", bridges[1].Interface)
	}

	if err := manager.Destroy(ctx, "br0"); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if sim.Node("br0") != nil || sim.Node("br0-if") != nil {
		t.Errorf("br0 nodes survived %v", sim.Nodes())
	}
	bridges, err = manager.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bridges) != 1 || bridges[0].Name != "br1" {
		t.Errorf("unexpected bridges after destroy %+v", bridges)
	}
}

func TestPortLifecycle(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}

	first, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	want := Port{Name: "ngeth0", Bridge: "br0", Hook: "link101", Type: "eiface", Interface: "ngeth0"}
	if first.Hook != want.Hook || first.Name != want.Name || first.Bridge != want.Bridge ||
		first.Type != want.Type || first.Interface != want.Interface {
		t.Errorf("created %+v, want %+v", first, want)
	}
	second, err := manager.CreatePort(ctx, "br0", 105)
	if err != nil {
		t.Fatalf("create second port: %v", err)
	}
	if second.Hook != "link105" {
		t.Errorf("second port hook %q, want link105", second.Hook)
	}
	third, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create third port: %v", err)
	}
	if third.Hook != "link106" {
		t.Errorf("third port hook %q, want link106, which is one past the highest port", third.Hook)
	}
	if err := manager.DestroyPort(ctx, "br0", "106"); err != nil {
		t.Fatalf("destroy third port: %v", err)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("got %d ports, want 2: %+v", len(ports), ports)
	}
	if ports[0].Name != "ngeth0" || ports[0].Hook != "link101" || ports[1].Name != "ngeth1" {
		t.Errorf("unexpected ports %+v", ports)
	}
	if sim.Node("ngeth0") == nil {
		t.Errorf("port node is missing")
	}

	all, err := manager.AllPorts(ctx)
	if err != nil {
		t.Fatalf("all ports: %v", err)
	}
	if !reflect.DeepEqual(all, ports) {
		t.Errorf("all ports %+v, want %+v", all, ports)
	}

	if err := manager.DestroyPort(ctx, "br0", "101"); err != nil {
		t.Fatalf("destroy port: %v", err)
	}
	ports, err = manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 || ports[0].Name != "ngeth1" {
		t.Errorf("unexpected ports after destroy %+v", ports)
	}
	if sim.Node("ngeth0") != nil {
		t.Errorf("port node survived %v", sim.Nodes())
	}
}

func TestBridgeErrors(t *testing.T) {
	ctx := context.Background()
	manager, _ := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := manager.Create(ctx, "br0", "", false); err == nil {
		t.Error("creating the same bridge twice succeeded")
	}
	if _, err := manager.Create(ctx, "br1", "with space", false); err == nil {
		t.Error("invalid interface name accepted")
	}
	if _, err := manager.Create(ctx, "name.too.long.for.netgraph.nodes", "", false); err == nil {
		t.Error("invalid node name accepted")
	}
	if _, err := manager.Create(ctx, "br2", "abcdefghijklmnop", false); err == nil {
		t.Error("interface name longer than 15 bytes accepted")
	}
	if _, err := manager.Get(ctx, "nope"); err == nil {
		t.Error("get of a missing bridge succeeded")
	}
	if err := manager.Destroy(ctx, "nope"); err == nil {
		t.Error("destroy of a missing bridge succeeded")
	}
	if _, err := manager.CreatePort(ctx, "nope", 0); err == nil {
		t.Error("port on a missing bridge succeeded")
	}
	if _, err := manager.CreatePort(ctx, "br0", maxPort+1); err == nil {
		t.Error("port number out of range accepted")
	}
	if err := manager.DestroyPort(ctx, "nope", "2"); err == nil {
		t.Error("destroy of a port on a missing bridge succeeded")
	}
}

func TestCreatePortNumbers(t *testing.T) {
	ctx := context.Background()
	manager, _ := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	first, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	if first.Hook != "link101" {
		t.Errorf("first port hook %q, want link101, the first number above 100", first.Hook)
	}
	if _, err := manager.CreatePort(ctx, "br0", 101); err == nil {
		t.Error("creating an existing port number succeeded")
	}
	if _, err := manager.CreatePort(ctx, "br0", -1); err == nil {
		t.Error("creating a negative port number succeeded")
	}
	explicit, err := manager.CreatePort(ctx, "br0", 105)
	if err != nil {
		t.Fatalf("create port 105: %v", err)
	}
	if explicit.Hook != "link105" {
		t.Errorf("hook %q, want link105", explicit.Hook)
	}
	next, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port after 105: %v", err)
	}
	if next.Hook != "link106" {
		t.Errorf("hook %q, want link106, one past the highest port", next.Hook)
	}
}

func TestCreatePortSkipsLowNumbers(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, number := range []int{2, 3, 100} {
		if _, err := manager.CreatePort(ctx, "br0", number); err != nil {
			t.Fatalf("create port %d: %v", number, err)
		}
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	if port.Hook != "link101" {
		t.Errorf("allocated %q, want link101: ports at or below 100 are never allocated", port.Hook)
	}
	busy := sim.Node("br0")
	if link := linkOn(busy, port.Hook); link == nil || link.PeerName != port.Name {
		t.Errorf("the allocated port is not connected: %+v", link)
	}
	if _, err := manager.CreatePort(ctx, "br0", 0); err != nil {
		t.Fatalf("create second port: %v", err)
	}
	if ports, err := manager.Ports(ctx, "br0"); err != nil || len(ports) != 5 {
		t.Fatalf("ports %+v, %v", ports, err)
	}
}

func TestPortDestroy(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}

	if err := manager.DestroyPort(ctx, "br0", "0"); err == nil {
		t.Error("destroying port 0 succeeded, it is the host interface")
	}
	if err := manager.DestroyPort(ctx, "br0", "link"); err == nil {
		t.Error("destroying a port without a number succeeded")
	}
	if err := manager.DestroyPort(ctx, "br0", "99"); err == nil {
		t.Error("destroying a port that does not exist succeeded")
	}
	if err := manager.DestroyPort(ctx, "br1", "2"); err == nil {
		t.Error("destroying a port on a bridge that does not exist succeeded")
	}
	if sim.Node(port.Name) == nil {
		t.Fatalf("failed destroy attempts took the port with them")
	}

	if err := manager.DestroyPort(ctx, "br0", strings.TrimPrefix(port.Hook, "link")); err != nil {
		t.Fatalf("destroy port by number: %v", err)
	}
	if sim.Node(port.Name) != nil {
		t.Errorf("port node survived")
	}
	if _, err := manager.CreatePort(ctx, "br0", 0); err != nil {
		t.Fatalf("create another port: %v", err)
	}
	if err := manager.DestroyPort(ctx, "br0", port.Hook); err != nil {
		t.Fatalf("destroy port by hook name: %v", err)
	}
	if sim.Node(port.Name) != nil {
		t.Errorf("port node survived")
	}
}

func TestGetReportsForeignBridge(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	bridgeNode := sim.AddNode("br9", "bridge")
	hostNode := sim.AddNode("ngeth7", "eiface")
	hostNode.Ifname = "br9"
	if err := sim.Link(bridgeNode, HostHook, hostNode, "ether"); err != nil {
		t.Fatalf("link: %v", err)
	}

	got, err := manager.Get(ctx, "br9")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Interface != "br9" || got.Ports != 0 {
		t.Errorf("unexpected bridge %+v", got)
	}
	if got.PeerName != "ngeth7" || got.PeerID != hostNode.ID || got.Filter != "" {
		t.Errorf("unexpected peer %+v", got)
	}
}

func TestPortNumber(t *testing.T) {
	for hook, want := range map[string]string{"link2": "2", "link105": "105", "ether": "ether"} {
		if got := (Port{Hook: hook}).Number(); got != want {
			t.Errorf("hook %q: got %q, want %q", hook, got, want)
		}
	}
}

func TestSortPortsIsNumeric(t *testing.T) {
	ports := []Port{
		{Bridge: "br0", Hook: "link10"},
		{Bridge: "br0", Hook: "link2"},
		{Bridge: "br0", Hook: "link0"},
		{Bridge: "br0", Hook: "ether"},
	}
	sortPorts(ports)
	want := []string{"link0", "link2", "link10", "ether"}
	for i, hook := range want {
		if ports[i].Hook != hook {
			t.Fatalf("position %d: got %q, want %q (%v)", i, ports[i].Hook, hook, ports)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

// TestPortsResolveFilter builds the topology the shell hooks use: an ethernet
// node behind an ng_bpf node, which is connected to a bridge port.
func TestPortsResolveFilter(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	if _, err := manager.CreatePort(ctx, "br0", 0); err != nil {
		t.Fatalf("create port: %v", err)
	}
	before := len(sim.Nodes())
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "eiface", "ngbridge", "ether"); err != nil {
		t.Fatalf("mkpeer eiface: %v", err)
	}
	nodes := sim.Nodes()
	if len(nodes) != before+1 {
		t.Fatalf("expected one new node, got %d", len(nodes)-before)
	}
	eiface := nodes[len(nodes)-1]
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", eiface.Name+":", "bpf", "ether", "jail"); err != nil {
		t.Fatalf("mkpeer bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "name", eiface.Name+":ether", "bpfngeth1"); err != nil {
		t.Fatalf("name bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "connect", "bpfngeth1:", "br0:", "bridge", "link200"); err != nil {
		t.Fatalf("connect: %v", err)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("got %d ports, want 2: %+v", len(ports), ports)
	}

	direct := ports[0]
	if direct.Hook != "link101" || direct.Name != "ngeth0" || direct.Type != "eiface" || direct.Filtered() {
		t.Errorf("unexpected direct port %+v", direct)
	}

	filtered := ports[1]
	if filtered.Hook != "link200" {
		t.Fatalf("second port hook %q, want link200", filtered.Hook)
	}
	if !filtered.Filtered() {
		t.Errorf("port behind a bpf node is not reported as filtered: %+v", filtered)
	}
	if filtered.PeerName != "bpfngeth1" || filtered.PeerType != "bpf" {
		t.Errorf("unexpected peer %+v", filtered)
	}
	if filtered.Name != eiface.Ifname || filtered.Type != "eiface" {
		t.Errorf("filtered port does not report the ethernet node behind the filter: %+v", filtered)
	}
	if filtered.Name == "bpfngeth1" || filtered.ID == filtered.PeerID {
		t.Errorf("filtered port still points at the filter: %+v", filtered)
	}
	if want := sim.Node("bpfngeth1").ID; filtered.PeerID != want {
		t.Errorf("filter id %q, want %q", filtered.PeerID, want)
	}

	if err := manager.DestroyPort(ctx, "br0", "200"); err != nil {
		t.Fatalf("destroy filtered port: %v", err)
	}
	for _, name := range []string{eiface.Name, "bpfngeth1"} {
		if sim.Node(name) != nil {
			t.Errorf("node %q survived", name)
		}
	}
}

func TestPortsInterfaceNeedsCurrentStack(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	created, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if ports[0].Name != created.Name || ports[0].Interface != created.Interface {
		t.Fatalf("unexpected port %+v", ports[0])
	}

	sim.HideInterface(created.Interface)
	ports, err = manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if ports[0].Name != created.Name || ports[0].Interface != "" {
		t.Errorf("interface of a port outside this network stack should be empty: %+v", ports[0])
	}
}

func TestPortWithoutDevice(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", "br0:", "bpf", "link2", "bridge"); err != nil {
		t.Fatalf("mkpeer bpf: %v", err)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want 1", len(ports))
	}
	if ports[0].Name != "" || ports[0].ID != "" || ports[0].Interface != "" {
		t.Errorf("a filter without a device should have no device fields: %+v", ports[0])
	}
	if !ports[0].Filtered() {
		t.Errorf("port should report its filter: %+v", ports[0])
	}
}

func TestParseInterfaceStatus(t *testing.T) {
	out := `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
	inet 127.0.0.1 netmask 0xff000000
ngeth3: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
	ether 58:9c:fc:10:3c:6e
	drivername: ngeth3
em0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
	drivername: em0
`
	interfaces := parseInterfaceStatus(out)
	want := map[string]string{"lo0": "", "ngeth3": "ngeth3", "em0": "em0"}
	for name, driver := range want {
		got, ok := interfaces[name]
		if !ok {
			t.Errorf("%s: missing", name)
			continue
		}
		if got != driver {
			t.Errorf("%s: driver %q, want %q", name, got, driver)
		}
	}
	if len(interfaces) != len(want) {
		t.Errorf("got %d interfaces, want %d: %v", len(interfaces), len(want), interfaces)
	}
	if got := parseInterfaceStatus(""); len(got) != 0 {
		t.Errorf("empty output: %v", got)
	}
}

func TestLocalInterfaceName(t *testing.T) {
	interfaces := map[string]string{
		"ngeth3":  "ngeth3",
		"eth0":    "em0",
		"epair0a": "epair0a",
		"unknown": "",
	}
	for name, want := range map[string]string{
		"ngeth3":  "ngeth3",
		"unknown": "unknown",
		"eth0":    "",
		"epair0a": "",
		"missing": "",
		"":        "",
	} {
		if got := localInterfaceName(interfaces, name); got != want {
			t.Errorf("%q: got %q, want %q", name, got, want)
		}
	}
	if got := localInterfaceName(nil, "ngeth3"); got != "" {
		t.Errorf("no interface list: got %q, want empty", got)
	}
}

// TestBridgeInterfaceResolvesFilter builds a bridge whose host interface hangs
// off an ng_bpf node on link0, and moves that interface out of this network
// stack.
func TestBridgeInterfaceResolvesFilter(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "eiface", "ngbridge", "ether"); err != nil {
		t.Fatalf("mkpeer eiface: %v", err)
	}
	eiface := sim.Nodes()[len(sim.Nodes())-1]
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", eiface.Name+":", "bpf", "ether", "host"); err != nil {
		t.Fatalf("mkpeer bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "name", eiface.Name+":ether", "bpfhost"); err != nil {
		t.Fatalf("name bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "bridge", "unused", HostHook); err != nil {
		t.Fatalf("mkpeer bridge: %v", err)
	}
	bridgeNode := sim.Nodes()[len(sim.Nodes())-1]
	if _, err := sim.Run(ctx, "ngctl", "name", "["+bridgeNode.ID+"]:", "br0"); err != nil {
		t.Fatalf("name bridge: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "connect", "bpfhost:", "br0:", "bridge", HostHook); err != nil {
		t.Fatalf("connect: %v", err)
	}

	bridge, err := manager.Get(ctx, "br0")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if bridge.Interface != eiface.Ifname {
		t.Errorf("interface %q, want %q", bridge.Interface, eiface.Ifname)
	}
	if bridge.PeerName != eiface.Name || bridge.PeerID != eiface.ID {
		t.Errorf("peer %q/%q, want %q/%q", bridge.PeerName, bridge.PeerID, eiface.Name, eiface.ID)
	}
	if bridge.Filter != "bpfhost" || bridge.FilterID == "" {
		t.Errorf("filter %q/%q, want bpfhost and its id", bridge.Filter, bridge.FilterID)
	}
	if want := sim.Node("bpfhost").ID; bridge.FilterID != want {
		t.Errorf("filter id %q, want %q", bridge.FilterID, want)
	}
	if bridge.Ports != 0 {
		t.Errorf("ports %d, want 0", bridge.Ports)
	}

	sim.HideInterface(eiface.Ifname)
	bridge, err = manager.Get(ctx, "br0")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if bridge.Interface != "" {
		t.Errorf("interface %q, want empty after the interface left the stack", bridge.Interface)
	}
}

// TestFilters builds a bridge with one plain port and one filtered port, with a
// program on both hooks of the filter.
func TestFilters(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	plain, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "eiface", "ngbridge", "ether"); err != nil {
		t.Fatalf("mkpeer eiface: %v", err)
	}
	eiface := sim.Nodes()[len(sim.Nodes())-1]
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", eiface.Name+":", "bpf", "ether", "jail"); err != nil {
		t.Fatalf("mkpeer bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "name", eiface.Name+":ether", "bpfngeth3"); err != nil {
		t.Fatalf("name bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "connect", "bpfngeth3:", "br0:", "bridge", "link105"); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "bpf", "unused", "spare"); err != nil {
		t.Fatalf("mkpeer spare bpf: %v", err)
	}

	going := cbpf.And(cbpf.EtherDst(mustMAC(t, "02:00:00:00:00:01")), cbpf.IPDst(mustIP(t, "10.0.0.5")))
	coming := cbpf.And(cbpf.EtherSrc(mustMAC(t, "02:00:00:00:00:01")), cbpf.IPSrc(mustIP(t, "10.0.0.5")))
	for hook, filter := range map[string]cbpf.Filter{"bridge": going, "jail": coming} {
		if err := setProgram(ctx, manager, "bpfngeth3", hook, filter); err != nil {
			t.Fatalf("set program on %s: %v", hook, err)
		}
	}

	filters, err := manager.Filters(ctx, "", "")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	if len(filters) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(filters), filters)
	}
	byHook := map[string]FilterHook{}
	for _, row := range filters {
		if row.Bridge != "br0" || row.Port != "105" {
			t.Errorf("unexpected row identity %+v", row)
		}
		if row.Node != "bpfngeth3" || row.NodeID == "" {
			t.Errorf("unexpected filter identity %+v", row)
		}
		if row.Program.Program.Len() == 0 || row.Expression == "" {
			t.Errorf("row without a program %+v", row)
		}
		byHook[row.Hook] = row
	}

	out, ok := byHook["bridge"]
	if !ok {
		t.Fatalf("hook facing the bridge is missing: %+v", filters)
	}
	if out.Peer != "br0" || out.Program.IfMatch != "jail" {
		t.Errorf("unexpected bridge facing row %+v", out)
	}

	in, ok := byHook["jail"]
	if !ok {
		t.Fatalf("device hook is missing: %+v", filters)
	}
	if in.Peer != eiface.Name || in.PeerID != eiface.ID || in.Program.IfMatch != "bridge" {
		t.Errorf("unexpected device row %+v", in)
	}

	byBridge, err := manager.Filters(ctx, "br0", "")
	if err != nil {
		t.Fatalf("filters of br0: %v", err)
	}
	if !reflect.DeepEqual(byBridge, filters) {
		t.Errorf("filters of br0: got %+v, want %+v", byBridge, filters)
	}

	byPort, err := manager.Filters(ctx, "br0", "105")
	if err != nil {
		t.Fatalf("filters of port 105: %v", err)
	}
	if !reflect.DeepEqual(byPort, filters) {
		t.Errorf("filters of port 105: got %+v, want %+v", byPort, filters)
	}

	plainFilters, err := manager.Filters(ctx, "br0", plain.Number())
	if err != nil {
		t.Fatalf("filters of a plain port: %v", err)
	}
	if len(plainFilters) != 0 {
		t.Errorf("plain port has filters: %+v", plainFilters)
	}

	for name, tc := range map[string]struct {
		bridge string
		port   string
	}{
		"missing port":   {bridge: "br0", port: "99"},
		"any bridge":     {bridge: "", port: "99"},
		"missing bridge": {bridge: "br9", port: ""},
	} {
		if _, err := manager.Filters(ctx, tc.bridge, tc.port); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// setProgram installs filter on hook of the ng_bpf node named node.
func setProgram(ctx context.Context, manager *Manager, node, hook string, filter cbpf.Filter) error {
	program, err := cbpf.Compile(filter, 0)
	if err != nil {
		return err
	}
	match := "jail"
	if hook == "jail" {
		match = "bridge"
	}
	ascii, err := program.NGctlProgram(hook, match, "")
	if err != nil {
		return err
	}
	_, err = manager.Ng.SetProgram(ctx, node+":", ascii)
	return err
}

func TestPortWithOtherNodeType(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	socket := sim.AddNode("ngsocket7", "socket")
	if _, err := sim.Run(ctx, "ngctl", "connect", "ngsocket7:", "br0:", "ether", "link2"); err != nil {
		t.Fatalf("connect socket: %v", err)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want 1: %+v", len(ports), ports)
	}
	port := ports[0]
	if port.PeerName != "ngsocket7" || port.PeerID != socket.ID || port.Type != "socket" {
		t.Errorf("unexpected port %+v", port)
	}
	if port.Interface != "" || port.Filtered() || port.FilterHook != "" {
		t.Errorf("socket port should have no interface and no filter: %+v", port)
	}
	if port.Name != "ngsocket7" || port.ID != socket.ID {
		t.Errorf("peer should be reported as the device: %+v", port)
	}

	filters, err := manager.Filters(ctx, "", "")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	if len(filters) != 0 {
		t.Errorf("got filters %+v, want none", filters)
	}
}

// TestBridgePeerWithOtherNodeType checks link0 connected to something that is
// neither an ethernet node nor a filter.
func TestBridgePeerWithOtherNodeType(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "bridge", "unused", HostHook); err != nil {
		t.Fatalf("mkpeer bridge: %v", err)
	}
	bridgeNode := sim.Nodes()[len(sim.Nodes())-1]
	if _, err := sim.Run(ctx, "ngctl", "name", "["+bridgeNode.ID+"]:", "br0"); err != nil {
		t.Fatalf("name bridge: %v", err)
	}
	socket := sim.AddNode("ngsocket7", "socket")
	if _, err := sim.Run(ctx, "ngctl", "connect", "ngsocket7:", "br0:", "ether", HostHook); err != nil {
		t.Fatalf("connect socket: %v", err)
	}

	got, err := manager.Get(ctx, "br0")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PeerName != "ngsocket7" || got.PeerID != socket.ID {
		t.Errorf("unexpected peer %+v", got)
	}
	if got.Interface != "" || got.Filter != "" {
		t.Errorf("socket peer should have no interface and no filter: %+v", got)
	}
	if got.Ports != 0 {
		t.Errorf("ports %d, want 0", got.Ports)
	}
}

// TestFiltersIncludeHostHook checks that a filter on link0 is listed under port
// 0, and that link0 without a filter contributes no rows.
func TestFiltersIncludeHostHook(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "eiface", "ngbridge", "ether"); err != nil {
		t.Fatalf("mkpeer eiface: %v", err)
	}
	eiface := sim.Nodes()[len(sim.Nodes())-1]
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", eiface.Name+":", "bpf", "ether", "host"); err != nil {
		t.Fatalf("mkpeer bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "name", eiface.Name+":ether", "bpfhost"); err != nil {
		t.Fatalf("name bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", ".", "bridge", "unused", HostHook); err != nil {
		t.Fatalf("mkpeer bridge: %v", err)
	}
	bridgeNode := sim.Nodes()[len(sim.Nodes())-1]
	if _, err := sim.Run(ctx, "ngctl", "name", "["+bridgeNode.ID+"]:", "br0"); err != nil {
		t.Fatalf("name bridge: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "connect", "bpfhost:", "br0:", "bridge", HostHook); err != nil {
		t.Fatalf("connect: %v", err)
	}
	program, err := cbpf.Compile(cbpf.EtherSrc(mustMAC(t, "02:00:00:00:00:01")), 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ascii, err := program.NGctlProgram("bridge", "host", "")
	if err != nil {
		t.Fatalf("ngctl program: %v", err)
	}
	if _, err := manager.Ng.SetProgram(ctx, "bpfhost:", ascii); err != nil {
		t.Fatalf("set program: %v", err)
	}

	filters, err := manager.Filters(ctx, "br0", "")
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	if len(filters) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(filters), filters)
	}
	for _, row := range filters {
		if row.Port != "0" || row.Node != "bpfhost" || row.Bridge != "br0" {
			t.Errorf("unexpected row %+v", row)
		}
	}

	byPort, err := manager.Filters(ctx, "br0", "0")
	if err != nil {
		t.Fatalf("filters of port 0: %v", err)
	}
	if !reflect.DeepEqual(byPort, filters) {
		t.Errorf("filters of port 0: got %+v, want %+v", byPort, filters)
	}

	// A bridge whose host hook is not filtered has no rows for port 0.
	plain, err := manager.Create(ctx, "br1", "", false)
	if err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	if plain.Filter != "" {
		t.Fatalf("bridge br1 should not be filtered: %+v", plain)
	}
	empty, err := manager.Filters(ctx, "br1", "0")
	if err != nil {
		t.Fatalf("filters of an unfiltered host hook: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("got %+v, want no rows", empty)
	}
}

func TestSetFilter(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}

	in, err := cbpf.Parse("ip src host 10.88.0.23")
	if err != nil {
		t.Fatalf("parse in: %v", err)
	}
	out, err := cbpf.Parse("ip dst host 10.88.0.23")
	if err != nil {
		t.Fatalf("parse out: %v", err)
	}
	filtered, err := manager.SetFilter(ctx, "br0", port.Number(), in, out)
	if err != nil {
		t.Fatalf("set filter: %v", err)
	}

	name := "bpf" + port.Name
	if !filtered.Filtered() || filtered.PeerName != name || filtered.PeerType != "bpf" {
		t.Errorf("port is not reported as filtered by %q: %+v", name, filtered)
	}
	if filtered.Name != port.Name || filtered.Interface != port.Interface {
		t.Errorf("filtered port lost its device: %+v", filtered)
	}
	if filtered.FilterHook != FilterMemberHook {
		t.Errorf("filter hook %q, want %q", filtered.FilterHook, FilterMemberHook)
	}

	for _, want := range []string{
		"ngctl rmhook br0: " + port.Hook,
		"ngctl mkpeer ngeth0: bpf ether member",
		"ngctl name ngeth0:ether " + name,
		"ngctl connect " + name + ": br0: bridge " + port.Hook,
	} {
		if !contains(sim.Calls(), want) {
			t.Errorf("missing %q in %v", want, sim.Calls())
		}
	}
	filter := sim.Node(name)
	if filter == nil || filter.Type != "bpf" {
		t.Fatalf("no bpf node %q in %v", name, sim.Nodes())
	}
	if link := linkOn(filter, FilterBridgeHook); link == nil || link.PeerName != "br0" || link.PeerHook != port.Hook {
		t.Errorf("bridge hook %+v, want br0:%s", link, port.Hook)
	}
	if link := linkOn(filter, FilterMemberHook); link == nil || link.PeerName != port.Name || link.PeerHook != "ether" {
		t.Errorf("member hook %+v, want %s:ether", link, port.Name)
	}

	filters, err := manager.Filters(ctx, "br0", port.Number())
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	if len(filters) != 2 {
		t.Fatalf("got %d filter hooks, want 2: %+v", len(filters), filters)
	}
	byHook := map[string]FilterHook{}
	for _, row := range filters {
		byHook[row.Hook] = row
	}
	member, ok := byHook[FilterMemberHook]
	if !ok {
		t.Fatalf("no program on the member hook: %+v", filters)
	}
	if member.Program.IfMatch != FilterBridgeHook || member.Program.IfNotMatch != FilterDebugHook {
		t.Errorf("member program wiring %+v, want bridge/debug", member.Program)
	}
	if member.Expression != "ip src host 10.88.0.23" {
		t.Errorf("member expression %q", member.Expression)
	}
	bridgeRow, ok := byHook[FilterBridgeHook]
	if !ok {
		t.Fatalf("no program on the bridge hook: %+v", filters)
	}
	if bridgeRow.Program.IfMatch != FilterMemberHook || bridgeRow.Program.IfNotMatch != FilterDebugHook {
		t.Errorf("bridge program wiring %+v, want member/debug", bridgeRow.Program)
	}
	if bridgeRow.Expression != "ip dst host 10.88.0.23" {
		t.Errorf("bridge expression %q", bridgeRow.Expression)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 || !ports[0].Filtered() {
		t.Errorf("unexpected ports %+v", ports)
	}

	if err := manager.DestroyPort(ctx, "br0", port.Number()); err != nil {
		t.Fatalf("destroy filtered port: %v", err)
	}
	for _, node := range []string{name, port.Name} {
		if sim.Node(node) != nil {
			t.Errorf("node %q survived", node)
		}
	}
}

func TestSetFilterAcceptsEverything(t *testing.T) {
	ctx := context.Background()
	manager, _ := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	if _, err := manager.SetFilter(ctx, "br0", port.Number(), cbpf.All(), cbpf.All()); err != nil {
		t.Fatalf("set filter: %v", err)
	}
	filters, err := manager.Filters(ctx, "br0", port.Number())
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	if len(filters) != 2 {
		t.Fatalf("got %d filter hooks, want 2", len(filters))
	}
	for _, row := range filters {
		if !strings.Contains(row.Expression, "len") {
			t.Errorf("an accepting program should not constrain the expression: %+v", row)
		}
	}
}

func TestSetFilterErrors(t *testing.T) {
	ctx := context.Background()
	manager, _ := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	if _, err := manager.CreatePort(ctx, "br0", 0); err != nil {
		t.Fatalf("create port: %v", err)
	}
	cases := []struct {
		bridge string
		port   string
		want   string
	}{
		{"br0", "0", "port 0 is the host interface"},
		{"br0", "abc", `port "abc" is not a number`},
		{"br0", "", "no port number given"},
		{"br0", "99", `bridge "br0" has no port 99`},
		{"nope", "2", `bridge "nope"`},
	}
	for _, c := range cases {
		_, err := manager.SetFilter(ctx, c.bridge, c.port, cbpf.All(), cbpf.All())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("bridge %q port %q: got %v, want one containing %q", c.bridge, c.port, err, c.want)
		}
	}
}

func TestSetFilterRestoresThePortOnFailure(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	squatter := sim.AddNode("bpf"+port.Name, "bpf")
	before := len(sim.Nodes())

	_, err = manager.SetFilter(ctx, "br0", port.Number(), cbpf.All(), cbpf.All())
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("got %v, want a name collision", err)
	}
	if len(sim.Nodes()) != before {
		t.Errorf("failed filter left nodes behind: %v", sim.Nodes())
	}
	if len(squatter.Links) != 0 {
		t.Errorf("the name collision modified the existing node: %+v", squatter.Links)
	}
	bridgeNode := sim.Node("br0")
	var link *ngctl.Link
	for i := range bridgeNode.Links {
		if bridgeNode.Links[i].Hook == port.Hook {
			link = &bridgeNode.Links[i]
		}
	}
	if link == nil || link.PeerName != port.Name || link.PeerHook != "ether" {
		t.Errorf("port was not reconnected to the bridge: %+v", link)
	}
	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 || ports[0].Filtered() || ports[0].Name != port.Name {
		t.Errorf("unexpected ports after the failure %+v", ports)
	}
}

// linkOn reports the link of a node on the given hook.
func linkOn(node *ngsim.Node, hook string) *ngctl.Link {
	if node == nil {
		return nil
	}
	for i := range node.Links {
		if node.Links[i].Hook == hook {
			return &node.Links[i]
		}
	}
	return nil
}

func TestSetFilterLeavesUnnamedDevicesUnnamed(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	device := sim.AddNode("", "eiface")
	if err := sim.Link(device, "ether", sim.Node("br0"), "link7"); err != nil {
		t.Fatalf("link device: %v", err)
	}
	before := len(sim.Nodes())

	filtered, err := manager.SetFilter(ctx, "br0", "7", cbpf.All(), cbpf.All())
	if err != nil {
		t.Fatalf("set filter: %v", err)
	}
	if len(sim.Nodes()) != before+1 {
		t.Fatalf("got %d nodes, want %d", len(sim.Nodes()), before+1)
	}
	if !filtered.Filtered() || filtered.PeerName != "" || filtered.PeerType != "bpf" {
		t.Errorf("unexpected port %+v", filtered)
	}
	for _, call := range sim.Calls() {
		if strings.HasPrefix(call, "ngctl name") && !strings.Contains(call, "br0-if") {
			t.Errorf("an unnamed device got a named filter: %s", call)
		}
	}
	var filter *ngsim.Node
	for _, node := range sim.Nodes() {
		if node.Type == "bpf" {
			filter = node
		}
	}
	if filter == nil || filter.Name != "" {
		t.Fatalf("filter node %+v, want an unnamed one", filter)
	}
	if link := linkOn(filter, FilterMemberHook); link == nil || link.PeerType != "eiface" {
		t.Errorf("member hook %+v, want the unnamed device", link)
	}
	if link := linkOn(filter, FilterBridgeHook); link == nil || link.PeerName != "br0" || link.PeerHook != "link7" {
		t.Errorf("bridge hook %+v, want br0:link7", link)
	}
	if filters, err := manager.Filters(ctx, "br0", "7"); err != nil || len(filters) != 2 {
		t.Errorf("filters %+v, %v", filters, err)
	}
	if err := manager.DestroyPort(ctx, "br0", "7"); err != nil {
		t.Fatalf("destroy port: %v", err)
	}
	if node := sim.Node("br0"); node == nil {
		t.Errorf("destroying the filtered port took the bridge with it")
	}
}

func TestSetFilterRejectsOtherDevices(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	before := len(sim.Nodes())
	for _, kind := range []string{"socket", "vlan", "one2many"} {
		device := sim.AddNode("", kind)
		hook := "link" + map[string]string{"socket": "11", "vlan": "12", "one2many": "13"}[kind]
		if err := sim.Link(device, "downstream", sim.Node("br0"), hook); err != nil {
			t.Fatalf("link %s: %v", kind, err)
		}
		_, err := manager.SetFilter(ctx, "br0", strings.TrimPrefix(hook, "link"), cbpf.All(), cbpf.All())
		if err == nil || !strings.Contains(err.Error(), "is connected to a "+kind+" node") {
			t.Errorf("%s device: got %v, want a refusal naming the node type", kind, err)
		}
		if node := sim.Node("br0"); node == nil {
			t.Fatalf("the bridge went away")
		}
	}
	if len(sim.Nodes()) != before+3 {
		t.Errorf("a refused filter changed the topology: %d nodes", len(sim.Nodes()))
	}
}

func TestSetFilterReconfiguresExistingFilter(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	device := sim.Node("ngeth0")
	if _, err := sim.Run(ctx, "ngctl", "rmhook", "br0:", port.Hook); err != nil {
		t.Fatalf("disconnect port: %v", err)
	}
	handler := sim.AddNode("bpfngeth0", "bpf")
	if err := sim.Link(handler, "jail", device, "ether"); err != nil {
		t.Fatalf("link jail: %v", err)
	}
	if err := sim.Link(handler, "bridge", sim.Node("br0"), port.Hook); err != nil {
		t.Fatalf("link bridge: %v", err)
	}
	debug := sim.AddNode("", "socket")
	if err := sim.Link(handler, "debug", debug, "dump"); err != nil {
		t.Fatalf("link debug: %v", err)
	}

	in, err := cbpf.Parse("ip src host 10.88.0.23")
	if err != nil {
		t.Fatalf("parse in: %v", err)
	}
	out, err := cbpf.Parse("ip dst host 10.88.0.23")
	if err != nil {
		t.Fatalf("parse out: %v", err)
	}
	calls := len(sim.Calls())
	filtered, err := manager.SetFilter(ctx, "br0", port.Number(), in, out)
	if err != nil {
		t.Fatalf("set filter: %v", err)
	}
	if !filtered.Filtered() || filtered.PeerName != "bpfngeth0" || filtered.FilterHook != "jail" {
		t.Errorf("unexpected port %+v", filtered)
	}
	for _, call := range sim.Calls()[calls:] {
		switch {
		case strings.HasPrefix(call, "ngctl show"):
		case strings.HasPrefix(call, "ngctl msg") && strings.Contains(call, "setprogram"):
		case strings.HasPrefix(call, "ifconfig"):
		case strings.HasPrefix(call, "ngctl list"):
		case strings.HasPrefix(call, "ngctl msg") && strings.Contains(call, "getifname"):
		default:
			t.Errorf("reconfiguring changed the topology: %s", call)
		}
	}

	filters, err := manager.Filters(ctx, "br0", port.Number())
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	byHook := map[string]FilterHook{}
	for _, row := range filters {
		byHook[row.Hook] = row
	}
	if len(byHook) != 3 {
		t.Fatalf("got %d hooks, want 3: %+v", len(byHook), filters)
	}
	dev, ok := byHook["jail"]
	if !ok {
		t.Fatalf("the device hook kept no program: %+v", filters)
	}
	if dev.Program.IfMatch != "bridge" || dev.Program.IfNotMatch != FilterDebugHook {
		t.Errorf("device hook wiring %+v", dev.Program)
	}
	if dev.Expression != "ip src host 10.88.0.23" {
		t.Errorf("device expression %q", dev.Expression)
	}
	br, ok := byHook["bridge"]
	if !ok {
		t.Fatalf("the bridge hook kept no program: %+v", filters)
	}
	if br.Program.IfMatch != "jail" || br.Program.IfNotMatch != FilterDebugHook {
		t.Errorf("bridge hook wiring %+v", br.Program)
	}
	if br.Expression != "ip dst host 10.88.0.23" {
		t.Errorf("bridge expression %q", br.Expression)
	}

	ambiguous := sim.AddNode("", "socket")
	if err := sim.Link(handler, "extra", ambiguous, "tap"); err != nil {
		t.Fatalf("link extra: %v", err)
	}
	if _, err := manager.SetFilter(ctx, "br0", port.Number(), in, out); err == nil ||
		!strings.Contains(err.Error(), "more than one hook towards a device: extra, jail") {
		t.Errorf("a filter with two device hooks: %v", err)
	}
}

func TestPortDeviceSkipsDebugHook(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	filtered, err := manager.SetFilter(ctx, "br0", port.Number(), cbpf.All(), cbpf.All())
	if err != nil {
		t.Fatalf("set filter: %v", err)
	}
	filter := "bpf" + port.Name
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", filter+":", "eiface", FilterDebugHook, "ether"); err != nil {
		t.Fatalf("attach a tap to the debug hook: %v", err)
	}
	tap := sim.Nodes()[len(sim.Nodes())-1]
	if link := linkOn(sim.Node(filter), FilterDebugHook); link == nil || link.PeerID != tap.ID {
		t.Fatalf("debug hook %+v, want %s", link, tap.Name)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want 1: %+v", len(ports), ports)
	}
	got := ports[0]
	if got.Name != filtered.Name || got.ID != filtered.ID || got.Interface != filtered.Interface {
		t.Errorf("port %+v resolves to %q/%q instead of the device %q/%q behind the member hook",
			got, got.Name, got.ID, filtered.Name, filtered.ID)
	}
	if got.FilterHook != FilterMemberHook {
		t.Errorf("filter hook %q, want %q", got.FilterHook, FilterMemberHook)
	}

	filters, err := manager.Filters(ctx, "br0", port.Number())
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	hooks := map[string]string{}
	for _, row := range filters {
		hooks[row.Hook] = row.Peer
	}
	if hooks[FilterDebugHook] != tap.Name {
		t.Errorf("the debug hook is not reported with its peer: %+v", filters)
	}
	if hooks[FilterMemberHook] != port.Name || hooks[FilterBridgeHook] != "br0" {
		t.Errorf("unexpected filter hooks %+v", hooks)
	}
}

func TestPortWithoutDeviceBehindDebug(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	handler := sim.AddNode("bpfngeth9", "bpf")
	if err := sim.Link(handler, FilterBridgeHook, sim.Node("br0"), "link9"); err != nil {
		t.Fatalf("link bridge: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", handler.Name+":", "eiface", FilterDebugHook, "ether"); err != nil {
		t.Fatalf("attach a tap: %v", err)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want 1: %+v", len(ports), ports)
	}
	got := ports[0]
	if !got.Filtered() || got.PeerName != handler.Name {
		t.Errorf("port is not reported as filtered by %q: %+v", handler.Name, got)
	}
	if got.Name != "" || got.ID != "" || got.Interface != "" {
		t.Errorf("the tap on the debug hook became the device: %+v", got)
	}
	if got.FilterHook != "" {
		t.Errorf("filter hook %q, want none", got.FilterHook)
	}
}

func TestAnalyzeFilter(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	br := sim.Node("br0")
	link := 2

	type built struct {
		filter *ngsim.Node
		device *ngsim.Node
	}
	build := func(name string, hooks ...string) built {
		t.Helper()
		filter := sim.AddNode(name, "bpf")
		device := sim.AddNode("", "eiface")
		for _, hook := range hooks {
			var err error
			switch hook {
			case FilterBridgeHook:
				link++
				err = sim.Link(filter, hook, br, "link"+strconv.Itoa(link))
			case FilterDebugHook:
				err = sim.Link(filter, hook, sim.AddNode("", "socket"), "dump")
			default:
				device = sim.AddNode("", "eiface")
				err = sim.Link(filter, hook, device, "ether")
			}
			if err != nil {
				t.Fatalf("link %s on %s: %v", hook, name, err)
			}
		}
		return built{filter, device}
	}
	analyze := func(filter *ngsim.Node) (FilterNode, error) {
		t.Helper()
		return manager.AnalyzeFilter(ctx, ngctl.Node{Name: br.Name, Type: br.Type, ID: br.ID},
			ngctl.Node{Name: filter.Name, Type: filter.Type, ID: filter.ID})
	}

	full := build("bpf-full", FilterBridgeHook, FilterMemberHook, FilterDebugHook)
	full.device.Name = "ngeth0"
	full.device.Ifname = "ngeth0"
	full.device.Driver = "ngeth0"
	node, err := analyze(full.filter)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if node.Node != "bpf-full" || node.NodeID != full.filter.ID {
		t.Errorf("identity %+v", node)
	}
	if node.OutHook != FilterBridgeHook || node.InHook != FilterMemberHook {
		t.Errorf("hooks %q/%q, want bridge/member", node.OutHook, node.InHook)
	}
	if node.Peer.Name != "ngeth0" || node.Peer.Type != "eiface" || node.Peer.ID != full.device.ID {
		t.Errorf("peer %+v, want the ethernet node", node.Peer)
	}
	if node.PeerHook != "ether" || node.DebugHook != FilterDebugHook {
		t.Errorf("peer hook %q debug %q", node.PeerHook, node.DebugHook)
	}

	plain := build("bpf-plain", FilterBridgeHook, "jail")
	node, err = analyze(plain.filter)
	if err != nil {
		t.Fatalf("analyze without a debug hook: %v", err)
	}
	if node.InHook != "jail" || node.OutHook != FilterBridgeHook || node.DebugHook != "" {
		t.Errorf("hooks %+v", node)
	}

	failures := []struct {
		name  string
		hooks []string
		want  string
	}{
		{"bpf-no-bridge", []string{"jail", FilterDebugHook}, `is not connected to bridge "br0"`},
		{"bpf-no-device", []string{FilterBridgeHook}, "has no hook towards a device"},
		{"bpf-two-devices", []string{FilterBridgeHook, "jail", "extra"}, "more than one hook towards a device: extra, jail"},
	}
	for _, c := range failures {
		got := build(c.name, c.hooks...)
		if _, err := analyze(got.filter); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want one containing %q", c.name, err, c.want)
		}
	}

	twice := sim.AddNode("bpf-two-bridges", "bpf")
	if err := sim.Link(twice, "one", br, "link88"); err != nil {
		t.Fatalf("link one: %v", err)
	}
	if err := sim.Link(twice, "two", br, "link89"); err != nil {
		t.Fatalf("link two: %v", err)
	}
	if _, err := analyze(twice); err == nil ||
		!strings.Contains(err.Error(), "more than one hook towards bridge") {
		t.Errorf("two hooks towards the bridge: %v", err)
	}
}

func TestFilteredPortNeedsAnEthernetDevice(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	other := sim.AddNode("mux0", "socket")
	if _, err := sim.Run(ctx, "ngctl", "mkpeer", other.Name+":", "bpf", "downstream", "jail"); err != nil {
		t.Fatalf("mkpeer bpf: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "name", other.Name+":downstream", "bpfmux0"); err != nil {
		t.Fatalf("name: %v", err)
	}
	if _, err := sim.Run(ctx, "ngctl", "connect", "bpfmux0:", "br0:", "bridge", "link2"); err != nil {
		t.Fatalf("connect: %v", err)
	}

	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want 1: %+v", len(ports), ports)
	}
	got := ports[0]
	if !got.Filtered() || got.PeerName != "bpfmux0" {
		t.Errorf("port is not reported as filtered: %+v", got)
	}
	if got.Name != "mux0" || got.Type != "socket" {
		t.Errorf("device %q (%q), want the socket node", got.Name, got.Type)
	}
	if got.Interface != "" {
		t.Errorf("a socket node got the interface %q", got.Interface)
	}

	if _, err := manager.SetFilter(ctx, "br0", "2", cbpf.All(), cbpf.All()); err == nil ||
		!strings.Contains(err.Error(), "is connected to a socket node") {
		t.Errorf("reconfiguring a filter in front of a socket: %v", err)
	}

	extra := sim.AddNode("", "socket")
	if err := sim.Link(sim.Node("bpfmux0"), "extra", extra, "tap"); err != nil {
		t.Fatalf("link extra: %v", err)
	}
	ports, err = manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if got := ports[0]; got.Name != "" || got.ID != "" || got.FilterHook != "" {
		t.Errorf("a filter that is not a port filter still reports a device: %+v", got)
	}
	if !ports[0].Filtered() {
		t.Errorf("the port stopped being reported as filtered: %+v", ports[0])
	}
}

func TestDeleteFilter(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	filtered, err := manager.SetFilter(ctx, "br0", port.Number(), cbpf.All(), cbpf.All())
	if err != nil {
		t.Fatalf("set filter: %v", err)
	}
	filter := "bpf" + port.Name
	if node := sim.Node(filter); node == nil {
		t.Fatalf("no filter node in %v", sim.Nodes())
	}

	got, err := manager.DeleteFilter(ctx, "br0", port.Number())
	if err != nil {
		t.Fatalf("delete filter: %v", err)
	}
	if got.Filtered() || got.Name != filtered.Name || got.ID != filtered.ID || got.FilterHook != "" {
		t.Errorf("port after deleting the filter %+v", got)
	}
	if sim.Node(filter) != nil {
		t.Errorf("the filter node survived")
	}
	bridgeNode := sim.Node("br0")
	link := linkOn(bridgeNode, port.Hook)
	if link == nil || link.PeerName != port.Name || link.PeerType != "eiface" || link.PeerHook != "ether" {
		t.Errorf("the device is not connected to the bridge again: %+v", link)
	}
	if device := sim.Node(port.Name); device == nil || len(device.Links) != 1 {
		t.Errorf("device %q has %v", port.Name, device)
	}
	calls := sim.Calls()
	if !contains(calls, "ngctl shutdown "+filter+":") {
		t.Errorf("missing shutdown in %v", calls)
	}
	if !contains(calls, "ngctl connect "+port.Name+": br0: ether "+port.Hook) {
		t.Errorf("missing reconnect in %v", calls)
	}

	filters, err := manager.Filters(ctx, "br0", port.Number())
	if err != nil {
		t.Fatalf("filters: %v", err)
	}
	if len(filters) != 0 {
		t.Errorf("filters remain after the delete: %+v", filters)
	}

	if _, err := manager.SetFilter(ctx, "br0", port.Number(), cbpf.All(), cbpf.All()); err != nil {
		t.Fatalf("filtering again: %v", err)
	}
	if err := manager.DestroyPort(ctx, "br0", port.Number()); err != nil {
		t.Fatalf("destroy filtered port: %v", err)
	}
	for _, name := range []string{port.Name, filter} {
		if sim.Node(name) != nil {
			t.Errorf("node %q survived", name)
		}
	}
}

func TestDeleteFilterErrors(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	cases := []struct {
		bridge string
		port   string
		want   string
	}{
		{"br0", "0", "port 0 is the host interface"},
		{"br0", "abc", `port "abc" is not a number`},
		{"br0", "9", `bridge "br0" has no port 9`},
		{"br0", port.Number(), `bridge "br0" port ` + port.Number() + ` has no filter`},
		{"nope", port.Number(), `bridge "nope"`},
	}
	for _, c := range cases {
		if _, err := manager.DeleteFilter(ctx, c.bridge, c.port); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("bridge %q port %q: got %v, want one containing %q", c.bridge, c.port, err, c.want)
		}
	}

	device := sim.Node("ngeth0")
	if _, err := sim.Run(ctx, "ngctl", "rmhook", "br0:", port.Hook); err != nil {
		t.Fatalf("disconnect port: %v", err)
	}
	mux := sim.AddNode("bpfmux", "bpf")
	if err := sim.Link(mux, "jail", sim.AddNode("mux0", "socket"), "downstream"); err != nil {
		t.Fatalf("link socket: %v", err)
	}
	if err := sim.Link(mux, "bridge", sim.Node("br0"), port.Hook); err != nil {
		t.Fatalf("link bridge: %v", err)
	}
	if _, err := manager.DeleteFilter(ctx, "br0", port.Number()); err == nil ||
		!strings.Contains(err.Error(), "is connected to a socket node, only ethernet nodes can be reconnected") {
		t.Errorf("deleting a filter in front of a socket: %v", err)
	}
	if sim.Node("bpfmux") == nil {
		t.Errorf("the refused filter was removed anyway")
	}
	if err := sim.Link(mux, "extra", device, "spare"); err != nil {
		t.Fatalf("link extra: %v", err)
	}
	if _, err := manager.DeleteFilter(ctx, "br0", port.Number()); err == nil ||
		!strings.Contains(err.Error(), "more than one hook towards a device") {
		t.Errorf("deleting a filter with two device hooks: %v", err)
	}
}

func TestDestroyPortTakesTheFilterWithIt(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 169691)
	if err != nil {
		t.Fatalf("create port named after a jail id: %v", err)
	}
	if port.Hook != "link169691" {
		t.Errorf("hook %q, want link169691", port.Hook)
	}
	filtered, err := manager.SetFilter(ctx, "br0", port.Number(), cbpf.All(), cbpf.All())
	if err != nil {
		t.Fatalf("set filter: %v", err)
	}
	filter := "bpf" + port.Name
	if err := manager.DestroyPort(ctx, "br0", port.Number()); err != nil {
		t.Fatalf("destroy port: %v", err)
	}
	for _, name := range []string{filtered.PeerName, filtered.Name, filter} {
		if sim.Node(name) != nil {
			t.Errorf("node %q survived the port destroy", name)
		}
	}
	if ports, err := manager.Ports(ctx, "br0"); err != nil || len(ports) != 0 {
		t.Errorf("ports %+v, %v", ports, err)
	}
}

func TestDestroyPortRemovesUnrecognisedFilters(t *testing.T) {
	ctx := context.Background()
	manager, sim := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	device := sim.AddNode("ngeth0", "eiface")
	device.Ifname = "ngeth0"
	filter := sim.AddNode("bpfngeth0", "bpf")
	if err := sim.Link(filter, "bridge", sim.Node("br0"), "link7"); err != nil {
		t.Fatalf("link bridge: %v", err)
	}
	if err := sim.Link(filter, "jail", device, "ether"); err != nil {
		t.Fatalf("link device: %v", err)
	}
	if err := sim.Link(filter, "extra", sim.AddNode("", "socket"), "tap"); err != nil {
		t.Fatalf("link extra: %v", err)
	}
	if _, err := manager.DeleteFilter(ctx, "br0", "7"); err == nil {
		t.Errorf("filter del accepted a filter with two device hooks")
	}
	if err := manager.DestroyPort(ctx, "br0", "7"); err != nil {
		t.Fatalf("destroy port: %v", err)
	}
	for _, name := range []string{"bpfngeth0", "ngeth0"} {
		if sim.Node(name) != nil {
			t.Errorf("node %q survived the port destroy", name)
		}
	}
}

func TestNotFoundErrors(t *testing.T) {
	ctx := context.Background()
	manager, _ := newTestManager()

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	if _, err := manager.CreatePort(ctx, "br0", 0); err != nil {
		t.Fatalf("create port: %v", err)
	}
	notFound := []struct {
		name string
		err  error
	}{
		{"destroy missing bridge", manager.DestroyPort(ctx, "nope", "101")},
		{"destroy missing port", manager.DestroyPort(ctx, "br0", "9")},
		{"delete missing bridge", second(manager.DeleteFilter(ctx, "nope", "101"))},
		{"delete missing port", second(manager.DeleteFilter(ctx, "br0", "9"))},
		{"delete on an unfiltered port", second(manager.DeleteFilter(ctx, "br0", "101"))},
	}
	for _, c := range notFound {
		if !errors.Is(c.err, ErrNotFound) {
			t.Errorf("%s: %v is not reported as not found", c.name, c.err)
		}
	}
	if err := manager.DestroyPort(ctx, "br0", "0"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("destroying the host interface is not a missing port: %v", err)
	}
	if err := manager.DestroyPort(ctx, "br0", "abc"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("a port that is not a number is not a missing port: %v", err)
	}
}

// second drops the port a filter command reports, for the tests.
func second(_ Port, err error) error {
	return err
}

// racingRunner stands in for another process that changes the same bridge
// while ngbridge works on it.
type racingRunner struct {
	*ngsim.Netgraph
	raced bool
}

func (r *racingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, "", name, args...)
}

func (r *racingRunner) RunInput(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	if len(args) > 4 && args[0] == "connect" && !r.raced {
		r.raced = true
		foreign := r.Netgraph.AddNode("", "eiface")
		if err := r.Netgraph.Link(foreign, "ether", r.Netgraph.Node("br0"), args[4]); err != nil {
			return nil, err
		}
	}
	return r.Netgraph.RunInput(ctx, stdin, name, args...)
}

func TestCreatePortRetriesAllocation(t *testing.T) {
	ctx := context.Background()
	sim := ngsim.New()
	runner := &racingRunner{Netgraph: sim}
	manager := &Manager{Ng: &ngctl.Ngctl{Runner: runner}, Ifconfig: "ifconfig"}

	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	port, err := manager.CreatePort(ctx, "br0", 0)
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	if port.Hook != "link102" {
		t.Errorf("allocated %q, want link102: the first attempt lost link101 to another process", port.Hook)
	}
	ports, err := manager.Ports(ctx, "br0")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("got %d ports, want 2: %+v", len(ports), ports)
	}
	if !runner.raced {
		t.Errorf("the test never raced the allocation")
	}
}

// foreignRunner creates an ethernet node just before an eiface creation script
// runs, so that the node list changes under ngbridge.
type foreignRunner struct {
	*ngsim.Netgraph
	foreign bool
}

func (r *foreignRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, "", name, args...)
}

func (r *foreignRunner) RunInput(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	if stdin != "" && !r.foreign {
		r.foreign = true
		node := r.Netgraph.AddNode("", "eiface")
		node.Ifname = r.Netgraph.InterfaceName()
	}
	return r.Netgraph.RunInput(ctx, stdin, name, args...)
}

func TestCreateEifaceFindsItsOwnNode(t *testing.T) {
	ctx := context.Background()
	sim := ngsim.New()
	runner := &foreignRunner{Netgraph: sim}
	manager := &Manager{Ng: &ngctl.Ngctl{Runner: runner}, Ifconfig: "ifconfig"}

	node, err := manager.createEiface(ctx, "")
	if err != nil {
		t.Fatalf("create eiface: %v", err)
	}
	if !runner.foreign {
		t.Fatalf("the test never created a foreign ethernet node")
	}
	foreign := sim.Nodes()[0]
	if node.ID == foreign.ID {
		t.Fatalf("took the ethernet node of another process: %+v", node)
	}
	if node.Name == "" || node.Name != node.Interface {
		t.Errorf("eiface %+v does not carry the interface the kernel assigned", node)
	}
	if sim.Node(node.Name) == nil || sim.Node(node.Name).ID != node.ID {
		t.Errorf("the created node %+v is not the one named %q", node, node.Name)
	}
}

func TestExists(t *testing.T) {
	ctx := context.Background()
	manager, _ := newTestManager()

	exists, err := manager.Exists(ctx, "br0")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if exists {
		t.Errorf("br0 exists before it was created")
	}
	if _, err := manager.Create(ctx, "br0", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	exists, err = manager.Exists(ctx, "br0")
	if err != nil || !exists {
		t.Errorf("br0 is not reported after it was created: %v, %v", exists, err)
	}
}
