package ngsim

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/b8b/libjail/ngbridge/internal/ngctl"
)

// Node is one simulated netgraph node.
type Node struct {
	Name   string
	Type   string
	ID     string
	Ifname string
	Driver string
	MAC    string
	MTU    int
	Addrs  []string
	// Jail is the jail the interface was moved into, empty while it is part of
	// the network stack this simulation stands for.
	Jail string
	// Hidden removes the interface from this stack without a jail, which the
	// tests use for interfaces of a stack this simulation does not model.
	Hidden   bool
	Links    []ngctl.Link
	Programs map[string]string
}

// Netgraph simulates the netgraph commands ngbridge issues, including the
// kernel side naming of ethernet nodes and interfaces. It implements
// ngctl.Runner, so it can stand in for the kernel in tests and in --dry-run.
type Netgraph struct {
	nodes  []*Node
	nextID int
	calls  []string
	// routes are the routing tables of the jails, by jail name.
	routes map[string][]string
	// tables are the pf tables, by table name.
	tables map[string][]string
	// socketHooks are the hooks of the socket node of the ngctl invocation that
	// is running, through which a node created in that same invocation can be
	// addressed. They belong to the process, so they are dropped when it ends.
	socketHooks map[string]*Node
}

// New returns an empty netgraph.
func New() *Netgraph {
	return &Netgraph{routes: map[string][]string{}, tables: map[string][]string{}}
}

// HideInterface removes an interface from what "ifconfig -l" reports, as if it
// had been moved into another network stack.
func (f *Netgraph) HideInterface(name string) {
	if node := f.byIface(name); node != nil {
		node.Hidden = true
	}
}

// hide records that the interface named name is no longer part of this stack.
func (f *Netgraph) hide(name, jail string) {
	if node := f.byIface(name); node != nil {
		node.Jail = jail
	}
}

// visible reports whether an interface is part of this network stack.
func visible(node *Node) bool {
	return node.Ifname != "" && node.Jail == "" && !node.Hidden
}

// Calls reports the commands that were issued.
func (f *Netgraph) Calls() []string {
	return append([]string(nil), f.calls...)
}

// InterfaceName reports the next interface name the kernel would assign.
func (f *Netgraph) InterfaceName() string {
	return f.freeIfaceName()
}

// Nodes reports every simulated node.
func (f *Netgraph) Nodes() []*Node {
	return append([]*Node(nil), f.nodes...)
}

// Node reports the node with the given name, if any.
func (f *Netgraph) Node(name string) *Node {
	return f.byName(name)
}

// NodeInfo describes a live netgraph node to seed the simulation with.
type NodeInfo struct {
	ID     string
	Name   string
	Type   string
	Ifname string
	Driver string
	Links  []ngctl.Link
}

// Seed adds live nodes to the simulation, so that a dry run starts from the
// real topology instead of an empty one.
func (f *Netgraph) Seed(nodes []NodeInfo) {
	for _, info := range nodes {
		f.nodes = append(f.nodes, &Node{
			Name: info.Name, Type: info.Type, ID: info.ID,
			Ifname: info.Ifname, Driver: info.Driver,
			Links: append([]ngctl.Link(nil), info.Links...),
		})
		if id, err := strconv.ParseUint(info.ID, 16, 32); err == nil && int(id) > f.nextID {
			f.nextID = int(id)
		}
	}
}

// AddNode adds a node without any connections.
func (f *Netgraph) AddNode(name, nodeType string) *Node {
	node := f.addNode(nodeType)
	node.Name = name
	return node
}

// Link connects two nodes.
func (f *Netgraph) Link(a *Node, aHook string, b *Node, bHook string) error {
	return f.link(a, aHook, b, bHook)
}

// Run implements ngctl.Runner.
func (f *Netgraph) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.RunInput(ctx, "", name, args...)
}

// RunInput implements ngctl.Runner. A script is what "ngctl -f -" reads, one
// command per line.
func (f *Netgraph) RunInput(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	f.socketHooks = map[string]*Node{}
	return f.dispatch(ctx, stdin, name, args...)
}

func (f *Netgraph) dispatch(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments")
	}
	if args[0] == "-f" {
		return f.script(ctx, stdin, name)
	}
	if name == "ifconfig" {
		return f.ifconfig(args)
	}
	if name == "route" {
		return nil, f.route(args)
	}
	if name == "pfctl" {
		return nil, f.pfctl(args)
	}
	switch args[0] {
	case "list":
		return []byte(f.list()), nil
	case "show":
		rest := withoutFlags(args[1:])
		if len(rest) != 1 {
			return nil, fmt.Errorf("show: not enough arguments")
		}
		out, err := f.show(rest[0])
		return []byte(out), err
	case "mkpeer":
		return nil, f.mkpeer(args[1:])
	case "name":
		return nil, f.rename(args[1:])
	case "connect":
		return nil, f.connect(args[1:])
	case "rmhook":
		return nil, f.rmhook(args[1:])
	case "shutdown":
		return nil, f.shutdown(args[1:])
	case "msg":
		return f.msg(args[1:])
	}
	return nil, fmt.Errorf("unsupported command %q", args[0])
}

// script runs the commands of an "ngctl -f -" invocation, one per line, and
// reports the output of all of them. A command that fails stops the script,
// which is what the real ngctl does.
func (f *Netgraph) script(ctx context.Context, stdin, name string) ([]byte, error) {
	out := []byte{}
	for _, line := range strings.Split(stdin, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		result, err := f.dispatch(ctx, "", name, fields...)
		out = append(out, result...)
		if err != nil {
			return out, fmt.Errorf("%q: %w", line, err)
		}
	}
	return out, nil
}

// withoutFlags drops the leading options of a command, which the simulation
// does not need.
func withoutFlags(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	return args
}

// Routes reports the routing table of a jail, one entry per line.
func (f *Netgraph) Routes(jail string) []string {
	return append([]string(nil), f.routes[jail]...)
}

// Table reports the addresses of a pf table.
func (f *Netgraph) Table(name string) []string {
	return append([]string(nil), f.tables[name]...)
}

// route simulates "route -j jail add ...".
func (f *Netgraph) route(args []string) error {
	jail := ""
	if len(args) > 1 && args[0] == "-j" {
		jail = args[1]
		args = args[2:]
	}
	if len(args) < 2 {
		return fmt.Errorf("route: not enough arguments")
	}
	switch args[0] {
	case "change":
		entry := strings.Join(args[1:], " ")
		key := routeKey(args[1:])
		replaced := false
		for i, known := range f.routes[jail] {
			if routeKey(strings.Fields(known)) != key {
				continue
			}
			f.routes[jail][i] = entry
			replaced = true
			break
		}
		if !replaced && !slices.Contains(f.routes[jail], entry) {
			f.routes[jail] = append(f.routes[jail], entry)
		}
		return nil
	case "add":
		entry := strings.Join(args[1:], " ")
		key := routeKey(args[1:])
		for _, known := range f.routes[jail] {
			if routeKey(strings.Fields(known)) == key {
				// The kernel refuses a route to a destination that is already
				// routed, which is what makes the plugin change it instead.
				return fmt.Errorf("route: route to %s: File exists", key)
			}
		}
		f.routes[jail] = append(f.routes[jail], entry)
		return nil
	case "delete", "del":
		entry := strings.Join(args[1:], " ")
		kept := f.routes[jail][:0]
		for _, known := range f.routes[jail] {
			if known != entry {
				kept = append(kept, known)
			}
		}
		f.routes[jail] = kept
		return nil
	}
	return fmt.Errorf("route: unsupported command %q", args[0])
}

// routeKey reports what identifies a route, so that a change replaces the route
// to the same destination. "default" and "-net 0.0.0.0/0" are the same route,
// which matters because a container whose loopback carries a host route of
// 0.0.0.0/0 starts with a default route that this simulation has to replace the
// same way the kernel does.
func routeKey(args []string) string {
	// Leading flags without a value carry nothing that identifies the route.
	for len(args) > 0 {
		switch args[0] {
		case "-4", "-6", "-static", "-nostatic", "-xresolve", "-cloning", "-reject", "-blackhole":
			args = args[1:]
			continue
		}
		break
	}
	if len(args) == 0 {
		return ""
	}
	key := args[0]
	switch args[0] {
	case "-net", "-host":
		if len(args) > 1 {
			key = args[0] + " " + args[1]
		}
	}
	switch key {
	case "default", "-net 0.0.0.0/0", "-net 0/0", "-net default":
		return "default"
	}
	return key
}

// pfctl simulates "-t table -T add|delete address".
func (f *Netgraph) pfctl(args []string) error {
	table := ""
	command := ""
	addresses := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			if i+1 < len(args) {
				table = args[i+1]
				i++
			}
		case "-T":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		default:
			addresses = append(addresses, args[i])
		}
	}
	if table == "" || command == "" {
		return fmt.Errorf("pfctl: unsupported arguments %v", args)
	}
	for _, address := range addresses {
		switch command {
		case "add":
			if !slices.Contains(f.tables[table], address) {
				f.tables[table] = append(f.tables[table], address)
			}
		case "delete":
			kept := f.tables[table][:0]
			for _, known := range f.tables[table] {
				if known != address {
					kept = append(kept, known)
				}
			}
			f.tables[table] = kept
		default:
			return fmt.Errorf("pfctl: unsupported command %q", command)
		}
	}
	return nil
}

func (f *Netgraph) ifconfig(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("ifconfig: not enough arguments")
	}
	jail := ""
	if args[0] == "-j" {
		if len(args) < 3 {
			return nil, fmt.Errorf("ifconfig: -j needs a jail and an argument")
		}
		jail = args[1]
		args = args[2:]
	}
	if len(args) > 0 && args[0] == "-D" {
		args = args[1:]
	}
	// A jail only has the interfaces that were moved into it, and this stack
	// only the ones that were not.
	if len(args) > 0 && args[0] == "-l" {
		names := []string{}
		for _, node := range f.nodes {
			if visible(node) {
				names = append(names, node.Ifname)
			}
		}
		return []byte(strings.Join(names, " ") + "\n"), nil
	}
	if len(args) > 0 && args[0] != "-l" && len(args) == 1 {
		node := f.byIface(args[0])
		if node == nil || node.Jail != jail || (jail == "" && !visible(node)) {
			return nil, fmt.Errorf("ifconfig: no such interface %q", args[0])
		}
		return []byte(f.status(node)), nil
	}
	if len(args) > 1 && args[0] == "-a" && slices.Contains(args, "-D") {
		var out strings.Builder
		for _, node := range f.nodes {
			if !visible(node) {
				continue
			}
			out.WriteString(f.status(node))
		}
		return []byte(out.String()), nil
	}
	if len(args) < 2 {
		return nil, fmt.Errorf("ifconfig: not enough arguments")
	}
	node := f.byIface(args[0])
	if node == nil {
		return nil, fmt.Errorf("ifconfig: no such interface %q", args[0])
	}
	if node.Jail != jail || (jail == "" && !visible(node)) {
		return nil, fmt.Errorf("ifconfig: no such interface %q", args[0])
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "name", "ether", "mtu", "vnet", "inet":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("ifconfig: %q needs a value", args[i])
			}
			value := args[i+1]
			i++
			switch args[i-1] {
			case "name":
				node.Ifname = value
			case "ether":
				node.MAC = value
			case "mtu":
				mtu, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("ifconfig: bad mtu %q", value)
				}
				node.MTU = mtu
			case "vnet":
				f.hide(node.Ifname, value)
			case "inet":
				if !slices.Contains(node.Addrs, value) {
					node.Addrs = append(node.Addrs, value)
				}
			}
		case "up", "down", "alias", "-alias":
		default:
			return nil, fmt.Errorf("ifconfig: unsupported argument %q", args[i])
		}
	}
	return nil, nil
}

// status renders one interface the way ifconfig does.
func (f *Netgraph) status(node *Node) string {
	mtu := node.MTU
	if mtu == 0 {
		mtu = 1500
	}
	out := fmt.Sprintf("%s: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu %d\n", node.Ifname, mtu)
	if node.MAC != "" {
		out += fmt.Sprintf("\tether %s\n", node.MAC)
	}
	for _, addr := range node.Addrs {
		out += fmt.Sprintf("\tinet %s\n", addr)
	}
	if node.Driver != "" {
		out += fmt.Sprintf("\tdrivername: %s\n", node.Driver)
	}
	return out
}

func (f *Netgraph) addNode(nodeType string) *Node {
	f.nextID++
	node := &Node{Type: nodeType, ID: fmt.Sprintf("%08x", f.nextID)}
	if nodeType == "eiface" {
		// A new ethernet node gets a random address from the kernel; here it is
		// derived from the node id so that the tests can rely on it.
		node.MAC = fmt.Sprintf("02:00:00:00:00:%02x", f.nextID%256)
	}
	f.nodes = append(f.nodes, node)
	return node
}

func (f *Netgraph) byName(name string) *Node {
	for _, node := range f.nodes {
		if node.Name != "" && node.Name == name {
			return node
		}
	}
	return nil
}

func (f *Netgraph) byID(id string) *Node {
	for _, node := range f.nodes {
		if node.ID == id {
			return node
		}
	}
	return nil
}

func (f *Netgraph) byIface(ifname string) *Node {
	for _, node := range f.nodes {
		if node.Ifname != "" && node.Ifname == ifname {
			return node
		}
	}
	return nil
}

func (f *Netgraph) remove(node *Node) {
	for _, other := range f.nodes {
		kept := other.Links[:0]
		for _, link := range other.Links {
			if link.PeerID != node.ID {
				kept = append(kept, link)
			}
		}
		other.Links = kept
	}
	kept := f.nodes[:0]
	for _, n := range f.nodes {
		if n != node {
			kept = append(kept, n)
		}
	}
	f.nodes = kept
}

func (f *Netgraph) link(a *Node, aHook string, b *Node, bHook string) error {
	if a.hook(aHook) != nil {
		return fmt.Errorf("%s already has hook %q", peerName(a), aHook)
	}
	if b.hook(bHook) != nil {
		return fmt.Errorf("%s already has hook %q", peerName(b), bHook)
	}
	a.Links = append(a.Links, ngctl.Link{
		Hook: aHook, PeerName: peerName(b), PeerType: b.Type, PeerID: b.ID, PeerHook: bHook,
	})
	b.Links = append(b.Links, ngctl.Link{
		Hook: bHook, PeerName: peerName(a), PeerType: a.Type, PeerID: a.ID, PeerHook: aHook,
	})
	return nil
}

func (n *Node) hook(name string) *ngctl.Link {
	for i, link := range n.Links {
		if link.Hook == name {
			return &n.Links[i]
		}
	}
	return nil
}

func peerName(node *Node) string {
	if node.Name == "" {
		return "<unnamed>"
	}
	return node.Name
}

// freeIfaceName mimics the kernel handing out the lowest free ngethN.
func (f *Netgraph) freeIfaceName() string {
	for i := 0; ; i++ {
		candidate := "ngeth" + strconv.Itoa(i)
		if f.byIface(candidate) == nil {
			return candidate
		}
	}
}

func (f *Netgraph) resolve(path string) (*Node, error) {
	ref, hook, _ := strings.Cut(path, ":")
	if ref == "." {
		node, ok := f.socketHooks[hook]
		if !ok {
			return nil, fmt.Errorf("no hook %q on the socket node", hook)
		}
		return node, nil
	}
	var node *Node
	if strings.HasPrefix(ref, "[") && strings.HasSuffix(ref, "]") {
		node = f.byID(strings.TrimSuffix(strings.TrimPrefix(ref, "["), "]"))
	} else {
		node = f.byName(ref)
	}
	if node == nil {
		return nil, fmt.Errorf("no node %q", ref)
	}
	if hook == "" {
		return node, nil
	}
	for _, link := range node.Links {
		if link.Hook == hook {
			return f.byID(link.PeerID), nil
		}
	}
	return nil, fmt.Errorf("no hook %q on node %q", hook, peerName(node))
}

func (f *Netgraph) list() string {
	out := fmt.Sprintf("There are %d total nodes:\n", len(f.nodes))
	for _, node := range f.nodes {
		if node.Name == "" {
			continue
		}
		out += fmt.Sprintf("  Name: %-15s Type: %-15s ID: %s   Num hooks: %d\n",
			node.Name, node.Type, node.ID, len(node.Links))
	}
	return out
}

func (f *Netgraph) show(path string) (string, error) {
	node, err := f.resolve(path)
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("  Name: %-15s Type: %-15s ID: %s   Num hooks: %d\n",
		peerName(node), node.Type, node.ID, len(node.Links))
	if len(node.Links) == 0 {
		return out, nil
	}
	out += "  Local hook      Peer name       Peer type    Peer ID         Peer hook\n"
	out += "  ----------      ---------       ---------    -------         ---------\n"
	for _, link := range node.Links {
		link = f.resolvePeer(link)
		out += fmt.Sprintf("  %-15s %-15s %-12s %-15s %-15s\n",
			link.Hook, link.PeerName, link.PeerType, link.PeerID, link.PeerHook)
	}
	return out, nil
}

// resolvePeer fills in the current name and type of a hook's peer, which the
// kernel reports as they are at the time of the query, not as they were when
// the hook was connected.
func (f *Netgraph) resolvePeer(link ngctl.Link) ngctl.Link {
	if peer := f.byID(link.PeerID); peer != nil {
		link.PeerName = peerName(peer)
		link.PeerType = peer.Type
	}
	return link
}

func (f *Netgraph) mkpeer(args []string) error {
	path, nodeType, ourHook, peerHook := args[0], args[1], args[2], args[3]
	if path == "." {
		node := f.addNode(nodeType)
		f.socketHooks[ourHook] = node
		if nodeType != "eiface" {
			return nil
		}
		node.Ifname = f.freeIfaceName()
		node.Driver = node.Ifname
		if f.byName(node.Ifname) == nil {
			node.Name = node.Ifname
		}
		return nil
	}
	parent, err := f.resolve(path)
	if err != nil {
		return err
	}
	node := f.addNode(nodeType)
	if err := f.link(parent, ourHook, node, peerHook); err != nil {
		f.remove(node)
		return err
	}
	return nil
}

func (f *Netgraph) rename(args []string) error {
	node, err := f.resolve(args[0])
	if err != nil {
		return err
	}
	name := args[1]
	if len(name) > 31 {
		return fmt.Errorf("name %q is too long", name)
	}
	if other := f.byName(name); other != nil && other != node {
		return fmt.Errorf("a node named %q already exists", name)
	}
	node.Name = name
	f.refreshPeers()
	return nil
}

// refreshPeers rewrites the peer names in every hook, because a node's name is
// looked up when the topology is queried, not when the hook was connected.
func (f *Netgraph) refreshPeers() {
	for _, node := range f.nodes {
		for i := range node.Links {
			if peer := f.byID(node.Links[i].PeerID); peer != nil {
				node.Links[i].PeerName = peerName(peer)
				node.Links[i].PeerType = peer.Type
			}
		}
	}
}

// connect follows ngctl's "connect [path] relpath hook peerhook": the paths
// come first, then the hook on path and the hook on the peer.
func (f *Netgraph) connect(args []string) error {
	from, err := f.resolve(args[0])
	if err != nil {
		return err
	}
	to, err := f.resolve(args[1])
	if err != nil {
		return err
	}
	return f.link(from, args[2], to, args[3])
}

func (f *Netgraph) rmhook(args []string) error {
	node, err := f.resolve(args[0])
	if err != nil {
		return err
	}
	link := node.hook(args[1])
	if link == nil {
		return fmt.Errorf("no hook %q on node %q", args[1], peerName(node))
	}
	node.Links = removeLink(node.Links, args[1])
	if peer := f.byID(link.PeerID); peer != nil {
		peer.Links = removeLink(peer.Links, link.PeerHook)
	}
	return nil
}

// removeLink drops the hook named hook from links.
func removeLink(links []ngctl.Link, hook string) []ngctl.Link {
	kept := links[:0]
	for _, link := range links {
		if link.Hook != hook {
			kept = append(kept, link)
		}
	}
	return kept
}

func (f *Netgraph) shutdown(args []string) error {
	node, err := f.resolve(args[0])
	if err != nil {
		return err
	}
	f.remove(node)
	return nil
}

func (f *Netgraph) msg(args []string) ([]byte, error) {
	node, err := f.resolve(args[0])
	if err != nil {
		return nil, err
	}
	if len(args) < 2 {
		return nil, fmt.Errorf("no message given")
	}
	switch args[1] {
	case "getifname":
		if node.Ifname == "" {
			return nil, fmt.Errorf("%s has no interface name", peerName(node))
		}
		return []byte(fmt.Sprintf("Rec'd response \"getifname\" (1) from %q:\nArgs:\t%q\n", args[0], node.Ifname)), nil
	case "setprogram":
		hook := hookField(args[2])
		if node.Programs == nil {
			node.Programs = map[string]string{}
		}
		node.Programs[hook] = args[2]
		return nil, nil
	case "getprogram":
		hook, err := strconv.Unquote(args[2])
		if err != nil {
			return nil, fmt.Errorf("hook %q: %w", args[2], err)
		}
		program, ok := node.Programs[hook]
		if !ok {
			// The kernel installs a default program that drops everything.
			program = fmt.Sprintf(`{ thisHook=%s bpf_prog_len=1 bpf_prog=[ { code=0x6 } ] }`, strconv.Quote(hook))
		}
		return []byte(fmt.Sprintf("Rec'd response \"getprogram\" (2) from %q:\nArgs:\t%s\n", args[0], program)), nil
	}
	return nil, fmt.Errorf("unsupported message %q", args[1:])
}

var hookFieldPattern = regexp.MustCompile(`thisHook="([^"]*)"`)

func hookField(program string) string {
	if match := hookFieldPattern.FindStringSubmatch(program); match != nil {
		return match[1]
	}
	return ""
}
