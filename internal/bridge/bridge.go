// Package bridge manages netgraph bridges and the ports connected to them.
//
// A bridge created here is a "bridge" node plus an ethernet node whose host
// interface carries the bridge name, connected through link0. A port is an
// ethernet node named after its interface, connected to the bridge through the
// next free link hook.
package bridge

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/b8b/libjail/ngbridge/internal/cbpf"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
)

const (
	// HostHook is the bridge hook the host interface is connected to.
	HostHook = "link0"
	// allocateAttempts is how often an allocated port number is retried when
	// another process takes it in the meantime.
	allocateAttempts = 5
	// firstAutoPort is the first port number handed out when the caller does not
	// pick one. Numbers up to 100 are left to whoever numbers its own ports
	// there, vm-bhyve starts at link0.
	firstAutoPort = 101
	// maxPort is the highest port number accepted. A port number becomes part of
	// the hook name linkN, which has NG_HOOKSIZ bytes, so this leaves room for
	// numbers as large as a jail id and still keeps the name short.
	maxPort = 999999999
	// eifaceHook is the socket node hook used while creating an ethernet node.
	eifaceHook = "ngbridge"
	// FilterBridgeHook is the ng_bpf hook that faces the bridge.
	FilterBridgeHook = "bridge"
	// FilterMemberHook is the ng_bpf hook that faces the device of the port.
	FilterMemberHook = "member"
	// FilterDebugHook receives the frames a filter program drops.
	FilterDebugHook = "debug"
	// NodeNameMax is NG_NODESIZ minus the terminating NUL.
	NodeNameMax = 31
	// InterfaceNameMax is IFNAMSIZ minus the terminating NUL.
	InterfaceNameMax = 15
	// unnamed is what ngctl prints for a node without a name.
	unnamed = "<unnamed>"
)

// ErrNotFound reports a bridge, port or filter that does not exist, so that a
// caller can tell "nothing to remove" from a real failure.
var ErrNotFound = errors.New("not found")

// ErrExists reports a bridge that is already there, which a caller that only
// wants the bridge to exist can accept.
var ErrExists = errors.New("already exists")

// notFoundError matches ErrNotFound and keeps the message it was built with.
type notFoundError struct{ message string }

func (e notFoundError) Error() string { return e.message }

func (e notFoundError) Is(target error) bool { return target == ErrNotFound }

func notFound(format string, args ...any) error {
	return notFoundError{message: fmt.Sprintf(format, args...)}
}

// Manager creates, lists and destroys bridges and ports.
type Manager struct {
	// Ng carries the netgraph commands.
	Ng *ngctl.Ngctl
	// Ifconfig is the ifconfig binary, "ifconfig" when empty.
	Ifconfig string
}

// New returns a Manager driving netgraph through ng.
func New(ng *ngctl.Ngctl) *Manager {
	return &Manager{Ng: ng, Ifconfig: "ifconfig"}
}

// Bridge describes a netgraph bridge node.
type Bridge struct {
	// Name and ID identify the bridge node.
	Name string
	ID   string
	// Ports is the number of hooks other than link0 that carry a port.
	Ports int
	// PeerName and PeerID identify the node behind link0, which is the
	// ethernet node of the host interface, or the ethernet node behind an
	// ng_bpf filter when one sits on link0. Both are empty when that node
	// could not be found.
	PeerName string
	PeerID   string
	// Interface is the interface name of that node, when an interface of that
	// name belongs to the network stack this tool runs in.
	Interface string
	// Filter and FilterID are the ng_bpf node on link0, empty when link0 is not
	// filtered.
	Filter   string
	FilterID string
}

// Port describes one connection to a bridge.
type Port struct {
	// Name and ID identify the node the port leads to. That is the peer of the
	// bridge hook, unless an ng_bpf node filters the port, in which case it is
	// the ethernet node behind that filter. Both stay empty when a filter is
	// present but no ethernet node is connected to it.
	Name string
	ID   string
	// Type is the type of that node, "eiface" for ethernet ports.
	Type string
	// Interface is the interface name the node reports, when an interface of
	// that name is part of the network stack this tool runs in.
	Interface string

	Bridge string
	Hook   string

	// PeerName, PeerID and PeerType describe the node directly connected to the
	// bridge hook. They differ from the fields above for filtered ports.
	PeerName string
	PeerID   string
	PeerType string
	// FilterHook is the hook of the filter node the device behind the port is
	// connected to, empty when the port is not filtered.
	FilterHook string
}

// Filtered reports whether an ng_bpf node sits between the bridge and the
// device the port leads to.
func (p Port) Filtered() bool {
	return p.PeerType == "bpf" && p.PeerID != "" && p.PeerID != p.ID
}

// Number is the bridge hook the port is connected to without its "link"
// prefix, which is how vm-bhyve and the netgraph examples name ports.
func (p Port) Number() string {
	return strings.TrimPrefix(p.Hook, "link")
}

// FilterNode is an ng_bpf node in front of a bridge port, read out into the
// hooks that make up a port filter: one hook towards the bridge, one towards
// the device, and an optional debug hook that is ignored.
type FilterNode struct {
	// Node and NodeID identify the ng_bpf node.
	Node   string
	NodeID string
	// OutHook is the hook that faces the bridge, InHook the hook that faces the
	// device.
	OutHook string
	InHook  string
	// Peer is the node behind InHook, and PeerHook the hook it is connected to.
	Peer     ngctl.Node
	PeerHook string
	// DebugHook is the name of the ignored debug hook, empty when the filter has
	// none.
	DebugHook string
}

// AnalyzeFilter reads the hooks of the ng_bpf node that filters a port of
// bridge. A port filter has exactly one hook towards the bridge, exactly one
// hook towards the device and optionally a debug hook, which receives the
// frames the programs rejected and is ignored here. A node whose hooks do not
// look like that is something this tool refuses to work with, so an error is
// returned instead of guessing which hook is meant.
func (m *Manager) AnalyzeFilter(ctx context.Context, bridge, filter ngctl.Node) (FilterNode, error) {
	details, err := m.Ng.Show(ctx, nodePath(filter.Name, filter.ID))
	if err != nil {
		return FilterNode{}, fmt.Errorf("filter %s: %w", path(filter), err)
	}
	node := FilterNode{Node: nodeName(details.Name), NodeID: details.ID}
	links := append([]ngctl.Link(nil), details.Links...)
	sortLinks(links)
	extra := []string{}
	for _, hook := range links {
		switch {
		case hook.PeerID == "" || hook.PeerID == details.ID:
			continue
		case hook.PeerID == bridge.ID:
			if node.OutHook != "" {
				return FilterNode{}, fmt.Errorf("filter %s has more than one hook towards bridge %q",
					path(details), bridge.Name)
			}
			node.OutHook = hook.Hook
		case hook.Hook == FilterDebugHook:
			node.DebugHook = hook.Hook
		case node.InHook == "":
			node.InHook = hook.Hook
			node.PeerHook = hook.PeerHook
			node.Peer = ngctl.Node{Name: nodeName(hook.PeerName), Type: hook.PeerType, ID: hook.PeerID}
		default:
			extra = append(extra, hook.Hook)
		}
	}
	if node.OutHook == "" {
		return FilterNode{}, fmt.Errorf("filter %s is not connected to bridge %q", path(details), bridge.Name)
	}
	if node.InHook == "" {
		return FilterNode{}, fmt.Errorf("filter %s has no hook towards a device", path(details))
	}
	if len(extra) > 0 {
		return FilterNode{}, fmt.Errorf("filter %s has more than one hook towards a device: %s",
			path(details), strings.Join(append([]string{node.InHook}, extra...), ", "))
	}
	return node, nil
}

// FilterHook is one hook of a filter node together with the program installed
// on it. An ng_bpf node filters the frames that arrive on a hook, so the hook
// that faces the bridge port filters what leaves the bridge, and the hooks that
// face the devices behind the filter filter what comes in from them.
type FilterHook struct {
	// Bridge and Port name the bridge port the filter sits in front of.
	Bridge string
	Port   string
	// Node and NodeID identify the ng_bpf node.
	Node   string
	NodeID string
	Hook   string
	Peer   string
	PeerID string
	// Program is the program installed on the hook, which is the kernel
	// default of "drop everything" until one is set.
	Program cbpf.HookProgram
	// Expression is the decompiled filter, empty when it could not be
	// decompiled, in which case Complete is false.
	Expression string
	Complete   bool
}

// Filters reports one row per hook of every filter in front of the ports
// selected by bridge and port. An empty bridge selects every bridge and an
// empty port every port; a port that has no filter contributes no rows.
func (m *Manager) Filters(ctx context.Context, bridge, port string) ([]FilterHook, error) {
	number := strings.TrimPrefix(port, "link")
	interfaces := m.localInterfaces(ctx)
	bridges, err := m.bridges(ctx, bridge)
	if err != nil {
		return nil, err
	}
	found := false
	filters := []FilterHook{}
	for _, bridgeNode := range bridges {
		details, err := m.Ng.Show(ctx, path(bridgeNode))
		if err != nil {
			return nil, err
		}
		links := append([]ngctl.Link(nil), details.Links...)
		sortLinks(links)
		for _, link := range links {
			candidate := m.portFromLink(ctx, nodeName(bridgeNode.Name), bridgeNode, link, interfaces)
			if number != "" && candidate.Number() != number {
				continue
			}
			found = true
			if !candidate.Filtered() {
				continue
			}
			hooks, err := m.filterHooks(ctx, candidate)
			if err != nil {
				return nil, err
			}
			filters = append(filters, hooks...)
		}
	}
	if number != "" && !found {
		if bridge == "" {
			return nil, fmt.Errorf("no bridge has port %q", port)
		}
		return nil, fmt.Errorf("bridge %q has no port %q", bridge, port)
	}
	return filters, nil
}

// bridges resolves the bridge nodes selected by name, or all of them.
func (m *Manager) bridges(ctx context.Context, name string) ([]ngctl.Node, error) {
	if name != "" {
		node, err := m.show(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("bridge %q: %w", name, err)
		}
		if node.Type != "bridge" {
			return nil, fmt.Errorf("%q is a %s node, not a bridge", name, node.Type)
		}
		return []ngctl.Node{node}, nil
	}
	nodes, err := m.Ng.List(ctx)
	if err != nil {
		return nil, err
	}
	bridges := []ngctl.Node{}
	for _, node := range nodes {
		if node.Type == "bridge" {
			bridges = append(bridges, node)
		}
	}
	return bridges, nil
}

// filterHooks reports every hook of the filter in front of a port with the
// program installed on it.
func (m *Manager) filterHooks(ctx context.Context, port Port) ([]FilterHook, error) {
	details, err := m.Ng.Show(ctx, "["+port.PeerID+"]:")
	if err != nil {
		return nil, err
	}
	links := append([]ngctl.Link(nil), details.Links...)
	sortLinks(links)
	hooks := make([]FilterHook, 0, len(links))
	for _, link := range links {
		hook := FilterHook{
			Bridge: port.Bridge, Port: port.Number(),
			Node: port.PeerName, NodeID: port.PeerID,
			Hook:   link.Hook,
			Peer:   nodeName(link.PeerName),
			PeerID: link.PeerID,
		}
		reply, err := m.Ng.GetProgram(ctx, "["+port.PeerID+"]:", link.Hook)
		if err != nil {
			return nil, fmt.Errorf("program of hook %q: %w", link.Hook, err)
		}
		hook.Program, err = cbpf.ParseHookProgram(reply)
		if err != nil {
			return nil, fmt.Errorf("program of hook %q: %w", link.Hook, err)
		}
		if decoded, err := hook.Program.Program.Decompile(); err == nil {
			hook.Expression = decoded.Expression()
			hook.Complete = decoded.Complete
		}
		hooks = append(hooks, hook)
	}
	return hooks, nil
}

// List reports every bridge in the netgraph system.
func (m *Manager) List(ctx context.Context) ([]Bridge, error) {
	nodes, err := m.Ng.List(ctx)
	if err != nil {
		return nil, err
	}
	interfaces := m.localInterfaces(ctx)
	bridges := []Bridge{}
	for _, node := range nodes {
		if node.Type != "bridge" {
			continue
		}
		details, err := m.Ng.Show(ctx, path(node))
		if err != nil {
			return nil, err
		}
		bridge, err := m.describe(ctx, details, interfaces)
		if err != nil {
			return nil, err
		}
		bridges = append(bridges, bridge)
	}
	sort.SliceStable(bridges, func(i, j int) bool {
		return bridges[i].Name < bridges[j].Name
	})
	return bridges, nil
}

// Exists reports whether a netgraph node with the given name is there, without
// depending on how a lookup of a missing node is reported.
func (m *Manager) Exists(ctx context.Context, name string) (bool, error) {
	nodes, err := m.Ng.List(ctx)
	if err != nil {
		return false, err
	}
	return find(nodes, name) != nil, nil
}

// Get reports the bridge named name.
func (m *Manager) Get(ctx context.Context, name string) (Bridge, error) {
	node, err := m.show(ctx, name)
	if err != nil {
		return Bridge{}, fmt.Errorf("bridge %q: %w", name, err)
	}
	if node.Type != "bridge" {
		return Bridge{}, fmt.Errorf("%q is a %s node, not a bridge", name, node.Type)
	}
	return m.describe(ctx, node, m.localInterfaces(ctx))
}

func (m *Manager) describe(ctx context.Context, node ngctl.Node, interfaces map[string]string) (Bridge, error) {
	bridge := Bridge{Name: node.Name, ID: node.ID}
	for _, link := range node.Links {
		if link.Hook == HostHook {
			if link.PeerType == "bpf" {
				bridge.Filter = nodeName(link.PeerName)
				bridge.FilterID = link.PeerID
			}
			if device, _, ok := m.portDevice(ctx, node, link); ok {
				bridge.PeerName = nodeName(device.Name)
				bridge.PeerID = device.ID
				bridge.Interface = m.interfaceName(ctx, device, interfaces)
			}
			continue
		}
		bridge.Ports++
	}
	return bridge, nil
}

// Create builds a bridge named name whose host interface is iface, which
// defaults to name, and brings that interface up when up is set.
func (m *Manager) Create(ctx context.Context, name, iface string, up bool) (Bridge, error) {
	if err := validateNodeName("bridge", name); err != nil {
		return Bridge{}, err
	}
	if iface == "" {
		iface = name
	}
	if err := validateInterfaceName(iface); err != nil {
		return Bridge{}, err
	}
	nodes, err := m.Ng.List(ctx)
	if err != nil {
		return Bridge{}, err
	}
	if find(nodes, name) != nil {
		return Bridge{}, fmt.Errorf("bridge %q: %w", name, ErrExists)
	}

	eiface, err := m.createEiface(ctx, iface+"-if")
	if err != nil {
		return Bridge{}, err
	}
	bridgepath := eiface.path + "ether"
	ok := false
	defer func() {
		if !ok {
			_ = m.Ng.Shutdown(ctx, bridgepath)
			_ = m.Ng.Shutdown(ctx, eiface.path)
		}
	}()

	if _, err := m.Ng.MkPeer(ctx, eiface.path, "bridge", "ether", HostHook); err != nil {
		return Bridge{}, fmt.Errorf("create bridge node: %w", err)
	}
	if err := m.Ng.Name(ctx, bridgepath, name); err != nil {
		return Bridge{}, fmt.Errorf("name bridge node: %w", err)
	}
	if err := m.renameInterface(ctx, eiface.Interface, iface); err != nil {
		return Bridge{}, err
	}
	if up {
		if err := m.ifconfig(ctx, iface, "up"); err != nil {
			return Bridge{}, err
		}
	}
	ok = true
	return m.Get(ctx, name)
}

// Destroy shuts down the bridge named name and its host interface.
func (m *Manager) Destroy(ctx context.Context, name string) error {
	node, err := m.show(ctx, name)
	if err != nil {
		return fmt.Errorf("bridge %q: %w", name, err)
	}
	if node.Type != "bridge" {
		return fmt.Errorf("%q is a %s node, not a bridge", name, node.Type)
	}
	var host *ngctl.Link
	for i := range node.Links {
		if node.Links[i].Hook == HostHook {
			host = &node.Links[i]
		}
	}
	if err := m.Ng.Shutdown(ctx, name+":"); err != nil {
		return fmt.Errorf("shutdown bridge %q: %w", name, err)
	}
	if host != nil {
		_ = m.Ng.Shutdown(ctx, linkPath(*host))
	}
	return nil
}

// Ports reports the ports connected to the bridge named bridge.
func (m *Manager) Ports(ctx context.Context, bridge string) ([]Port, error) {
	node, err := m.show(ctx, bridge)
	if err != nil {
		return nil, fmt.Errorf("bridge %q: %w", bridge, err)
	}
	ports := m.ports(ctx, bridge, node, m.localInterfaces(ctx))
	sortPorts(ports)
	return ports, nil
}

// sortPorts orders ports by bridge hook number, "link2" before "link10".
func sortPorts(ports []Port) {
	sort.SliceStable(ports, func(i, j int) bool {
		return hookLess(ports[i].Hook, ports[j].Hook)
	})
}

func hookNumber(hook string) (int, bool) {
	number, err := strconv.Atoi(strings.TrimPrefix(hook, "link"))
	return number, err == nil
}

// AllPorts reports the ports of every bridge.
func (m *Manager) AllPorts(ctx context.Context) ([]Port, error) {
	bridges, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	interfaces := m.localInterfaces(ctx)
	ports := []Port{}
	for _, bridge := range bridges {
		node, err := m.show(ctx, bridge.Name)
		if err != nil {
			return nil, fmt.Errorf("bridge %q: %w", bridge.Name, err)
		}
		ports = append(ports, m.ports(ctx, bridge.Name, node, interfaces)...)
	}
	sort.SliceStable(ports, func(i, j int) bool {
		return ports[i].Bridge < ports[j].Bridge
	})
	return ports, nil
}

func (m *Manager) ports(ctx context.Context, bridge string, node ngctl.Node, interfaces map[string]string) []Port {
	ports := []Port{}
	for _, link := range node.Links {
		if link.Hook == HostHook {
			continue
		}
		ports = append(ports, m.portFromLink(ctx, bridge, node, link, interfaces))
	}
	return ports
}

// portFromLink describes one bridge hook, whether it carries a port or the
// host interface.
func (m *Manager) portFromLink(ctx context.Context, bridge string, node ngctl.Node, link ngctl.Link, interfaces map[string]string) Port {
	port := Port{
		Bridge:   bridge,
		Hook:     link.Hook,
		PeerName: nodeName(link.PeerName),
		PeerID:   link.PeerID,
		PeerType: link.PeerType,
	}
	if device, hook, ok := m.portDevice(ctx, node, link); ok {
		port.Name = nodeName(device.Name)
		port.ID = device.ID
		port.Type = device.Type
		port.FilterHook = hook
		port.Interface = m.interfaceName(ctx, device, interfaces)
	}
	return port
}

// portDevice reports the node behind a bridge hook. Nodes other than ng_bpf
// filters are reported as they are, whether or not they have an interface; a
// filter is read with AnalyzeFilter, which reports the device behind its in
// hook, and a filter that does not look like a port filter has no device.
func (m *Manager) portDevice(ctx context.Context, bridge ngctl.Node, link ngctl.Link) (ngctl.Node, string, bool) {
	peer := ngctl.Node{Name: nodeName(link.PeerName), Type: link.PeerType, ID: link.PeerID}
	if link.PeerType != "bpf" {
		return peer, "", true
	}
	filter, err := m.AnalyzeFilter(ctx, bridge, peer)
	if err != nil {
		return ngctl.Node{}, "", false
	}
	return filter.Peer, filter.InHook, true
}

// interfaceName reports the interface of device, when an interface of that name
// belongs to the network stack this tool runs in.
func (m *Manager) interfaceName(ctx context.Context, device ngctl.Node, interfaces map[string]string) string {
	if device.Type != "eiface" || device.ID == "" {
		return ""
	}
	name, err := m.Ng.IfName(ctx, "["+device.ID+"]:")
	if err != nil {
		return ""
	}
	return localInterfaceName(interfaces, name)
}

func sortLinks(links []ngctl.Link) {
	sort.SliceStable(links, func(i, j int) bool {
		return hookLess(links[i].Hook, links[j].Hook)
	})
}

func hookLess(a, b string) bool {
	left, leftOK := hookNumber(a)
	right, rightOK := hookNumber(b)
	switch {
	case leftOK && rightOK:
		return left < right
	case leftOK != rightOK:
		return leftOK
	default:
		return a < b
	}
}

// CreatePort attaches a new ethernet port to the bridge named bridge, leaving
// the interface down for the caller to move into a jail. A port number of zero
// allocates one past the highest port in use and never one at or below 100,
// otherwise the given number is used and it is an error when the bridge already
// has that port.
func (m *Manager) CreatePort(ctx context.Context, bridge string, number int) (Port, error) {
	attempts := 1
	if number == 0 {
		attempts = allocateAttempts
	}
	explicit := number != 0
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		port, retry, err := m.createPort(ctx, bridge, number)
		if err == nil {
			return port, nil
		}
		last = err
		if !retry {
			return Port{}, err
		}
		if !explicit {
			number = 0
		}
	}
	if explicit {
		return Port{}, last
	}
	return Port{}, fmt.Errorf("could not allocate a free port on bridge %q after %d attempts: %w", bridge, attempts, last)
}

// createPort makes one attempt at attaching a port. retry reports that the
// attempt lost a race for the number it picked, which only happens when the
// caller left the number to this package.
func (m *Manager) createPort(ctx context.Context, bridge string, number int) (Port, bool, error) {
	target, err := m.show(ctx, bridge)
	if err != nil {
		return Port{}, false, fmt.Errorf("bridge %q: %w", bridge, err)
	}
	if target.Type != "bridge" {
		return Port{}, false, fmt.Errorf("%q is a %s node, not a bridge", bridge, target.Type)
	}
	explicit := number != 0
	if !explicit {
		number = nextPort(target.Links)
	}
	if number < 1 || number > maxPort {
		return Port{}, false, fmt.Errorf("port %d is out of range", number)
	}
	hook := portHook(number)
	if portInUse(target.Links, hook) {
		if explicit {
			return Port{}, false, fmt.Errorf("bridge %q already has port %d", bridge, number)
		}
		return Port{}, true, fmt.Errorf("bridge %q already has port %d", bridge, number)
	}

	eiface, err := m.createEiface(ctx, "")
	if err != nil {
		return Port{}, false, err
	}
	if err := m.Ng.Connect(ctx, eiface.path, "ether", bridge+":", hook); err != nil {
		_ = m.Ng.Shutdown(ctx, eiface.path)
		if !explicit && errors.Is(err, ngctl.ErrAddressInUse) {
			return Port{}, true, fmt.Errorf("connect port %d: %w", number, err)
		}
		return Port{}, false, fmt.Errorf("connect port %d: %w", number, err)
	}
	return Port{
		Bridge: bridge, Hook: hook,
		Name: eiface.Name, ID: eiface.ID, Type: "eiface", Interface: eiface.Interface,
		PeerName: eiface.Name, PeerID: eiface.ID, PeerType: "eiface",
	}, false, nil
}

// nextPort reports one past the highest port number in use, and never a number
// at or below 100, which is where other tools put their own ports.
func nextPort(links []ngctl.Link) int {
	highest := firstAutoPort - 1
	for _, link := range links {
		number, ok := hookNumber(link.Hook)
		if ok && number > highest {
			highest = number
		}
	}
	return highest + 1
}

func portHook(number int) string {
	return "link" + strconv.Itoa(number)
}

func portInUse(links []ngctl.Link, hook string) bool {
	for _, link := range links {
		if link.Hook == hook {
			return true
		}
	}
	return false
}

// DestroyPort shuts down the port with the given number on the bridge named
// bridge. The number is the bridge hook without its "link" prefix, as reported
// by port list; "link2" and "2" are both accepted. A port behind an ng_bpf
// filter takes the filter node with it.
func (m *Manager) DestroyPort(ctx context.Context, bridge, port string) error {
	number := strings.TrimPrefix(port, "link")
	if number == "" {
		return fmt.Errorf("no port number given")
	}
	if number == "0" {
		return fmt.Errorf("port 0 is the host interface of bridge %q, destroy the bridge instead", bridge)
	}
	if _, err := portNumber(number); err != nil {
		return err
	}
	target, err := m.show(ctx, bridge)
	if err != nil {
		return fmt.Errorf("bridge %q: %w", bridge, err)
	}
	if target.Type != "bridge" {
		return fmt.Errorf("%q is a %s node, not a bridge", bridge, target.Type)
	}
	ports := m.ports(ctx, bridge, target, m.localInterfaces(ctx))
	for _, candidate := range ports {
		if candidate.Number() != number {
			continue
		}
		if !candidate.Filtered() {
			if candidate.ID == "" {
				return nil
			}
			if err := m.Ng.Shutdown(ctx, nodePath(candidate.Name, candidate.ID)); err != nil {
				return fmt.Errorf("shutdown port %s: %w", number, err)
			}
			return nil
		}
		filter := ngctl.Node{Name: candidate.PeerName, Type: candidate.PeerType, ID: candidate.PeerID}
		devices := []ngctl.Node{}
		if candidate.ID != "" {
			devices = append(devices, ngctl.Node{Name: candidate.Name, Type: candidate.Type, ID: candidate.ID})
		} else {
			devices = m.ethernetPeers(ctx, filter, target)
		}
		if err := m.Ng.Shutdown(ctx, nodePath(filter.Name, filter.ID)); err != nil {
			return fmt.Errorf("shutdown filter of port %s: %w", number, err)
		}
		for _, device := range devices {
			if err := m.Ng.Shutdown(ctx, nodePath(device.Name, device.ID)); err != nil {
				return fmt.Errorf("shutdown device of port %s: %w", number, err)
			}
		}
		return nil
	}
	return notFound("bridge %q has no port %q", bridge, port)
}

// ethernetPeers reports the ethernet nodes connected to the hooks of a filter,
// skipping the bridge and the debug hook. It is what port destroy uses to take
// the devices of a port with it, even when the filter is not one that
// AnalyzeFilter understands.
func (m *Manager) ethernetPeers(ctx context.Context, filter ngctl.Node, bridge ngctl.Node) []ngctl.Node {
	details, err := m.Ng.Show(ctx, nodePath(filter.Name, filter.ID))
	if err != nil {
		return nil
	}
	devices := []ngctl.Node{}
	seen := map[string]bool{}
	for _, hook := range details.Links {
		if hook.PeerID == "" || hook.PeerID == bridge.ID || hook.PeerID == filter.ID {
			continue
		}
		if hook.Hook == FilterDebugHook || hook.PeerType != "eiface" || seen[hook.PeerID] {
			continue
		}
		seen[hook.PeerID] = true
		devices = append(devices, ngctl.Node{Name: nodeName(hook.PeerName), Type: hook.PeerType, ID: hook.PeerID})
	}
	return devices
}

// SetFilter filters a port: it inserts an ng_bpf node in front of it, or
// reconfigures the node that is already there. Frames are filtered on the hook
// they arrive on, so in filters what comes from the port and out what goes to
// it, and frames that neither program accepts are handed to the filter's debug
// hook. An empty filter accepts every frame.
//
// Only an ethernet node can be put behind a filter, because netgraph has no way
// to move a connection and only ng_eiface(4) survives a node without hooks.
func (m *Manager) SetFilter(ctx context.Context, bridge, port string, in, out cbpf.Filter) (Port, error) {
	number, err := portNumber(port)
	if err != nil {
		return Port{}, err
	}
	target, err := m.show(ctx, bridge)
	if err != nil {
		return Port{}, fmt.Errorf("bridge %q: %w", bridge, err)
	}
	if target.Type != "bridge" {
		return Port{}, fmt.Errorf("%q is a %s node, not a bridge", bridge, target.Type)
	}
	hook := portHook(number)
	var link *ngctl.Link
	for i := range target.Links {
		if target.Links[i].Hook == hook {
			link = &target.Links[i]
			break
		}
	}
	if link == nil {
		return Port{}, fmt.Errorf("bridge %q has no port %d", bridge, number)
	}
	if link.PeerID == "" {
		return Port{}, fmt.Errorf("port %d of bridge %q is not connected to a node", number, bridge)
	}
	if link.PeerType == "bpf" {
		return m.reconfigureFilter(ctx, bridge, number, target, *link, in, out)
	}
	if link.PeerType != "eiface" {
		return Port{}, fmt.Errorf("port %d of bridge %q is connected to a %s node, only ethernet nodes can be filtered",
			number, bridge, link.PeerType)
	}
	if link.PeerHook == "" {
		return Port{}, fmt.Errorf("cannot tell which hook of port %d faces the bridge", number)
	}
	peer := ngctl.Node{Name: nodeName(link.PeerName), Type: link.PeerType, ID: link.PeerID}
	memberProgram, bridgeProgram, err := filterPrograms(in, out)
	if err != nil {
		return Port{}, err
	}

	if err := m.Ng.RmHook(ctx, bridge+":", hook); err != nil {
		return Port{}, fmt.Errorf("disconnect port %d from the bridge: %w", number, err)
	}
	// Connect the device again first: netgraph destroys the hook on the other
	// side of a link when one side goes away, and an ethernet node that has no
	// hook at all is only kept alive by its node type. Attaching the filter to
	// the device hands it a hook again in a single command; the bridge follows
	// once the filter exists.
	device := nodePath(peer.Name, peer.ID)
	reconnect := func() {
		_ = m.Ng.Connect(ctx, device, link.PeerHook, bridge+":", hook)
	}
	filterPath, err := m.Ng.MkPeer(ctx, device, "bpf", link.PeerHook, FilterMemberHook)
	if err != nil {
		reconnect()
		return Port{}, fmt.Errorf("create filter node: %w", err)
	}
	restore := func() {
		_ = m.Ng.Shutdown(ctx, filterPath)
		reconnect()
	}
	filter := filterPath
	if name := filterName(peer); name != "" {
		if err := m.Ng.Name(ctx, filterPath, name); err != nil {
			restore()
			return Port{}, fmt.Errorf("name filter node: %w", err)
		}
		filter = name + ":"
	}
	if err := m.Ng.Connect(ctx, filter, FilterBridgeHook, bridge+":", hook); err != nil {
		restore()
		return Port{}, fmt.Errorf("connect filter to bridge %q: %w", bridge, err)
	}
	for _, program := range []struct{ hook, text string }{
		{FilterBridgeHook, bridgeProgram},
		{FilterMemberHook, memberProgram},
	} {
		if _, err := m.Ng.SetProgram(ctx, filter, program.text); err != nil {
			restore()
			return Port{}, fmt.Errorf("program of hook %q: %w", program.hook, err)
		}
	}
	ports, err := m.Ports(ctx, bridge)
	if err != nil {
		return Port{}, err
	}
	for _, candidate := range ports {
		if candidate.Number() == strconv.Itoa(number) {
			return candidate, nil
		}
	}
	return Port{}, fmt.Errorf("bridge %q has no port %d after filtering it", bridge, number)
}

// DeleteFilter removes the ng_bpf node in front of a port and connects the
// device to the bridge again. The filter has to be one that AnalyzeFilter
// understands and its device has to be an ethernet node, because that is what
// is connected to the bridge afterwards.
//
// Removing the filter shuts its node down, which destroys both of its
// connections, and the device gets a hook again with the connect that follows.
// Only ng_eiface(4) survives that moment without hooks, which is why any other
// device is refused.
func (m *Manager) DeleteFilter(ctx context.Context, bridge, port string) (Port, error) {
	number, err := portNumber(port)
	if err != nil {
		return Port{}, err
	}
	target, err := m.show(ctx, bridge)
	if err != nil {
		return Port{}, fmt.Errorf("bridge %q: %w", bridge, err)
	}
	if target.Type != "bridge" {
		return Port{}, fmt.Errorf("%q is a %s node, not a bridge", bridge, target.Type)
	}
	hook := portHook(number)
	var link *ngctl.Link
	for i := range target.Links {
		if target.Links[i].Hook == hook {
			link = &target.Links[i]
			break
		}
	}
	if link == nil {
		return Port{}, notFound("bridge %q has no port %d", bridge, number)
	}
	if link.PeerType != "bpf" {
		return Port{}, notFound("bridge %q port %d has no filter", bridge, number)
	}
	node, err := m.AnalyzeFilter(ctx, target, ngctl.Node{Name: nodeName(link.PeerName), Type: link.PeerType, ID: link.PeerID})
	if err != nil {
		return Port{}, err
	}
	if node.Peer.Type != "eiface" {
		return Port{}, fmt.Errorf("filter %s is connected to a %s node, only ethernet nodes can be reconnected",
			nodePath(node.Node, node.NodeID), node.Peer.Type)
	}
	if err := m.Ng.Shutdown(ctx, nodePath(node.Node, node.NodeID)); err != nil {
		return Port{}, fmt.Errorf("shutdown filter: %w", err)
	}
	if err := m.Ng.Connect(ctx, nodePath(node.Peer.Name, node.Peer.ID), node.PeerHook, bridge+":", hook); err != nil {
		return Port{}, fmt.Errorf("connect %q to bridge %q port %d again: %w",
			nodePath(node.Peer.Name, node.Peer.ID), bridge, number, err)
	}
	ports, err := m.Ports(ctx, bridge)
	if err != nil {
		return Port{}, err
	}
	for _, candidate := range ports {
		if candidate.Number() == strconv.Itoa(number) {
			return candidate, nil
		}
	}
	return Port{}, fmt.Errorf("bridge %q has no port %d after deleting its filter", bridge, number)
}

// reconfigureFilter installs new programs on the ng_bpf node that already sits
// in front of a port, leaving the topology alone. The hook that faces the
// bridge carries what goes out to the port, the hook that faces the device what
// comes in, and both hand what they do not accept to the debug hook.
func (m *Manager) reconfigureFilter(ctx context.Context, bridge string, number int, target ngctl.Node, link ngctl.Link, in, out cbpf.Filter) (Port, error) {
	node, err := m.AnalyzeFilter(ctx, target, ngctl.Node{Name: nodeName(link.PeerName), Type: link.PeerType, ID: link.PeerID})
	if err != nil {
		return Port{}, err
	}
	if node.Peer.Type != "eiface" {
		return Port{}, fmt.Errorf("filter %s is connected to a %s node, only ethernet nodes can be filtered",
			nodePath(node.Node, node.NodeID), node.Peer.Type)
	}
	programs := []struct {
		hook, text string
	}{}
	if text, err := hookProgram(out, node.OutHook, node.InHook); err != nil {
		return Port{}, fmt.Errorf("compile the outgoing filter: %w", err)
	} else {
		programs = append(programs, struct{ hook, text string }{node.OutHook, text})
	}
	if text, err := hookProgram(in, node.InHook, node.OutHook); err != nil {
		return Port{}, fmt.Errorf("compile the incoming filter: %w", err)
	} else {
		programs = append(programs, struct{ hook, text string }{node.InHook, text})
	}
	for _, program := range programs {
		if _, err := m.Ng.SetProgram(ctx, nodePath(node.Node, node.NodeID), program.text); err != nil {
			return Port{}, fmt.Errorf("program of hook %q: %w", program.hook, err)
		}
	}
	ports, err := m.Ports(ctx, bridge)
	if err != nil {
		return Port{}, err
	}
	for _, candidate := range ports {
		if candidate.Number() == strconv.Itoa(number) {
			return candidate, nil
		}
	}
	return Port{}, fmt.Errorf("bridge %q has no port %d after filtering it", bridge, number)
}

// hookProgram compiles one direction of a filter into the ASCII form of
// NGM_BPF_SET_PROGRAM for the hook it is installed on.
func hookProgram(filter cbpf.Filter, thisHook, ifMatch string) (string, error) {
	program, err := cbpf.Compile(filter, 0)
	if err != nil {
		return "", err
	}
	return program.NGctlProgram(thisHook, ifMatch, FilterDebugHook)
}

// filterPrograms compiles the two directions of a filter into the ASCII form
// of NGM_BPF_SET_PROGRAM: what arrives on a hook is compared, and what the
// program accepts is handed to the hook that faces the other side, so frames
// from the port go on to the bridge and frames from the bridge go on to the
// port. Everything else goes to the debug hook.
func filterPrograms(in, out cbpf.Filter) (member, bridge string, err error) {
	member, err = hookProgram(in, FilterMemberHook, FilterBridgeHook)
	if err != nil {
		return "", "", fmt.Errorf("incoming filter: %w", err)
	}
	bridge, err = hookProgram(out, FilterBridgeHook, FilterMemberHook)
	if err != nil {
		return "", "", fmt.Errorf("outgoing filter: %w", err)
	}
	return member, bridge, nil
}

// filterName names a new filter node after the device it filters, as the
// netgraph examples do. A device without a name, or one whose name leaves no
// room for the prefix, gets a filter without a name as well.
func filterName(peer ngctl.Node) string {
	if peer.Name == "" || len("bpf"+peer.Name) > NodeNameMax {
		return ""
	}
	return "bpf" + peer.Name
}

// portNumber parses a port number, "link2" and "2" both being accepted. Port 0
// is the host interface and not a port.
func portNumber(port string) (int, error) {
	text := strings.TrimPrefix(port, "link")
	if text == "" {
		return 0, fmt.Errorf("no port number given")
	}
	number, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("port %q is not a number", port)
	}
	if number == 0 {
		return 0, fmt.Errorf("port 0 is the host interface, not a port")
	}
	if number < 0 || number > maxPort {
		return 0, fmt.Errorf("port %d is out of range", number)
	}
	return number, nil
}

// eiface is a freshly created ethernet node, addressed by path.
type eiface struct {
	path      string
	Name      string
	Interface string
	ID        string
}

// createEiface creates an ethernet node through an anonymous socket node and
// reports it. The hook on that socket node is named so that the new node can be
// found through it, because the node list is shared with everything else that
// runs netgraph commands and another process may create an ethernet node at the
// same time. The kernel picks the interface name, ngethN.
func (m *Manager) createEiface(ctx context.Context, name string) (eiface, error) {
	out, err := m.Ng.Script(ctx,
		"mkpeer . eiface "+eifaceHook+" ether",
		"show -n .:"+eifaceHook,
	)
	if err != nil {
		return eiface{}, fmt.Errorf("create ethernet node: %w", err)
	}
	node, err := ngctl.ParseShow(out)
	if err != nil {
		return eiface{}, fmt.Errorf("find the ethernet node that was just created: %w", err)
	}
	ifname, err := m.Ng.IfName(ctx, path(node))
	if err != nil {
		_ = m.Ng.Shutdown(ctx, path(node))
		return eiface{}, fmt.Errorf("name of the new ethernet node: %w", err)
	}
	if name != "" {
		if err := m.Ng.Name(ctx, path(node), name); err != nil {
			_ = m.Ng.Shutdown(ctx, path(node))
			return eiface{}, fmt.Errorf("name ethernet node %q: %w", name, err)
		}
		node.Name = name
	}
	return eiface{path: path(node), Name: node.Name, Interface: ifname, ID: node.ID}, nil
}

func (m *Manager) renameInterface(ctx context.Context, from, to string) error {
	if from == to {
		return nil
	}
	if err := m.ifconfig(ctx, from, "name", to); err != nil {
		return fmt.Errorf("rename interface %q to %q: %w", from, to, err)
	}
	return nil
}

func (m *Manager) ifconfig(ctx context.Context, args ...string) error {
	_, err := m.run(ctx, m.ifconfigPath(), args...)
	return err
}

func (m *Manager) show(ctx context.Context, name string) (ngctl.Node, error) {
	node, err := m.Ng.Show(ctx, name+":")
	if errors.Is(err, ngctl.ErrNoSuchNode) {
		return ngctl.Node{}, notFound("%v", err)
	}
	return node, err
}

func nodeName(name string) string {
	if name == unnamed {
		return ""
	}
	return name
}

// nodePath addresses a node by name when it has one, so that the commands that
// are printed and run stay readable.
func nodePath(name, id string) string {
	return path(ngctl.Node{Name: name, ID: id})
}

func path(node ngctl.Node) string {
	if node.Name != "" && node.Name != unnamed {
		return node.Name + ":"
	}
	return "[" + node.ID + "]:"
}

func linkPath(link ngctl.Link) string {
	if link.PeerName != "" && link.PeerName != unnamed {
		return link.PeerName + ":"
	}
	return "[" + link.PeerID + "]:"
}

func find(nodes []ngctl.Node, name string) *ngctl.Node {
	for i, node := range nodes {
		if node.Name == name {
			return &nodes[i]
		}
	}
	return nil
}

func validateNodeName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%s name is empty", kind)
	}
	if len(name) > NodeNameMax {
		return fmt.Errorf("%s name %q is longer than %d bytes", kind, name, NodeNameMax)
	}
	for _, r := range name {
		if r == '.' || r == ':' || r <= ' ' {
			return fmt.Errorf("%s name %q contains %q", kind, name, r)
		}
	}
	return nil
}

func validateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name is empty")
	}
	if len(name) > InterfaceNameMax {
		return fmt.Errorf("interface name %q is longer than %d bytes", name, InterfaceNameMax)
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("interface name %q contains %q", name, r)
	}
	return nil
}
