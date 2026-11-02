package netavark

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
	"github.com/b8b/libjail/ngbridge/internal/cbpf"
	"github.com/b8b/libjail/ngbridge/internal/guard"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
)

const (
	// bridgeDriver is the only network driver this command implements.
	bridgeDriver = "bridge"
	// natTableOption is the network option that names the pf table the addresses
	// of the containers are entered in, which is what a masquerading rule on the
	// host matches against. An empty value turns masquerading off.
	natTableOption = "nat_table"
	// defaultNatTable is the table a masqueraded network uses when it names
	// none, which is the one the CNI plugin fills as well.
	defaultNatTable = "cni-nat"
	// mtuOption is the network option that overrides the MTU of the container
	// interfaces.
	mtuOption = "mtu"
	// defaultConfigDir is the netavark run directory podman uses on FreeBSD,
	// which the state is kept below when it does not name one with --config.
	defaultConfigDir = "/var/run/containers/networks"
)

// plugin connects jails to netgraph bridges, the way netavark's bridge driver
// connects network namespaces to bridges on Linux.
type plugin struct {
	// manager drives netgraph and ifconfig.
	manager *bridge.Manager
	// configDir is the netavark run directory.
	configDir string
}

// newPlugin returns a plugin that drives manager and keeps its state in
// configDir. A nil manager runs ngctl and ifconfig as child processes, an empty
// configDir uses defaultConfigDir.
func newPlugin(manager *bridge.Manager, configDir string) *plugin {
	if manager == nil {
		manager = bridge.New(&ngctl.Ngctl{})
	}
	if configDir == "" {
		configDir = defaultConfigDir
	}
	return &plugin{manager: manager, configDir: configDir}
}

// setup connects the container to every network of the request and reports the
// interfaces it got, one block per network. When a network fails, the networks
// that were set up before it are torn down again, so that a failed invocation
// does not leave ports behind.
func (p *plugin) setup(ctx context.Context, req *request, namespace string) (map[string]statusBlock, error) {
	if len(req.Networks) == 0 {
		return nil, errors.New("the request names no network to set up")
	}
	names := slices.Sorted(maps.Keys(req.Networks))
	status := make(map[string]statusBlock, len(names))
	done := make([]State, 0, len(names))
	for index, name := range names {
		block, state, err := p.setupNetwork(ctx, req, name, req.Networks[name], namespace, index)
		if err != nil {
			for _, previous := range done {
				_ = p.teardownState(ctx, previous)
			}
			return nil, err
		}
		done = append(done, state)
		status[name] = block
	}
	return status, nil
}

// teardown removes the port of every network of the request, which succeeds
// when there is nothing left to remove. The jail itself is not touched: podman
// tears it down after the network.
func (p *plugin) teardown(ctx context.Context, req *request, namespace string) error {
	names := slices.Sorted(maps.Keys(req.Networks))
	errs := []error{}
	for _, name := range names {
		state, exists, err := loadState(p.configDir, name, req.ContainerID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !exists {
			continue
		}
		if err := p.teardownState(ctx, state); err != nil {
			errs = append(errs, fmt.Errorf("network %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// setupNetwork connects the container to one network.
func (p *plugin) setupNetwork(ctx context.Context, req *request, name string, options perNetworkOptions, namespace string, index int) (statusBlock, State, error) {
	network, ok := req.NetworkInfo[name]
	if !ok {
		return statusBlock{}, State{}, fmt.Errorf("no definition for network %q", name)
	}
	if network.Driver != "" && network.Driver != bridgeDriver {
		return statusBlock{}, State{}, fmt.Errorf("network %q uses the %q driver, this command implements %q",
			name, network.Driver, bridgeDriver)
	}
	if namespace == "" {
		return statusBlock{}, State{}, fmt.Errorf("network %q: no jail to set the network up in", name)
	}
	bridgeName := network.NetworkInterface
	if bridgeName == "" {
		return statusBlock{}, State{}, fmt.Errorf("network %q names no interface to bridge to", name)
	}
	ifName := options.InterfaceName
	if ifName == "" {
		ifName = "eth" + strconv.Itoa(index)
	}
	addresses, err := addressesOf(network.Subnets, options.StaticIPs)
	if err != nil {
		return statusBlock{}, State{}, fmt.Errorf("network %q: %w", name, err)
	}
	mac := options.StaticMAC
	if mac == "" {
		mac = derivedMAC(name, req.ContainerID)
	}
	// A port left behind by an earlier invocation is removed first, which is
	// what a container that was started twice without a teardown in between
	// leaves.
	if stale, exists, err := loadState(p.configDir, name, req.ContainerID); err != nil {
		return statusBlock{}, State{}, err
	} else if exists {
		_ = p.teardownState(ctx, stale)
	}
	if err := p.ensureBridge(ctx, bridgeName, network.Subnets); err != nil {
		return statusBlock{}, State{}, err
	}
	port, err := p.manager.CreatePort(ctx, bridgeName, 0)
	if err != nil {
		return statusBlock{}, State{}, fmt.Errorf("create a port on bridge %q: %w", bridgeName, err)
	}
	state := State{
		Network:   name,
		Container: req.ContainerID,
		IfName:    ifName,
		Bridge:    bridgeName,
		Port:      port.Number(),
		Device:    port.Interface,
		MAC:       mac,
		Addresses: addresses,
		NatTable:  natTableOf(network),
	}
	if state.Device == "" {
		state.Device = port.Name
	}
	mtu, err := mtuOf(network)
	if err != nil {
		_ = p.manager.DestroyPort(ctx, bridgeName, state.Port)
		return statusBlock{}, State{}, fmt.Errorf("network %q: %w", name, err)
	}
	if mtu == 0 {
		mtu = p.manager.InterfaceMTU(ctx, bridgeName)
	}
	if err := p.configurePort(ctx, namespace, state, network.Routes, mtu); err != nil {
		_ = p.manager.DestroyPort(ctx, bridgeName, state.Port)
		return statusBlock{}, State{}, err
	}
	if err := saveState(p.configDir, state); err != nil {
		_ = p.teardownState(ctx, state)
		return statusBlock{}, State{}, fmt.Errorf("save the state of %s: %w", ifName, err)
	}
	block := statusBlock{Interfaces: map[string]netInterface{ifName: {Subnets: addresses, MacAddress: mac}}}
	return block, state, nil
}

// ensureBridge creates the bridge when it does not exist yet and puts the
// gateways of its subnets on it, because the containers cannot route without
// them.
func (p *plugin) ensureBridge(ctx context.Context, name string, subnets []subnet) error {
	exists, err := p.manager.Exists(ctx, name)
	if err != nil {
		return fmt.Errorf("look at bridge %q: %w", name, err)
	}
	if !exists {
		if _, err := p.manager.Create(ctx, name, "", true); err != nil && !errors.Is(err, bridge.ErrExists) {
			return fmt.Errorf("create bridge %q: %w", name, err)
		}
	}
	if _, err := p.manager.Get(ctx, name); err != nil {
		return err
	}
	for _, subnet := range subnets {
		if subnet.Gateway == "" {
			continue
		}
		_, network, err := net.ParseCIDR(subnet.Subnet)
		if err != nil {
			return fmt.Errorf("subnet %q: %w", subnet.Subnet, err)
		}
		ones, _ := network.Mask.Size()
		wanted := fmt.Sprintf("%s/%d", subnet.Gateway, ones)
		status, err := p.manager.RunIfconfig(ctx, name)
		if err == nil && hasAddress(status, subnet.Gateway) {
			continue
		}
		if _, err := p.manager.RunIfconfig(ctx, name, "inet", wanted); err != nil && !alreadyThere(err) {
			return fmt.Errorf("put the gateway %s on bridge %q: %w", wanted, name, err)
		}
	}
	return nil
}

// configurePort gives the port its address, moves it into the jail and sets the
// interface and the routes up there.
func (p *plugin) configurePort(ctx context.Context, namespace string, state State, routes []route, mtu int) error {
	if _, err := p.manager.RunIfconfig(ctx, state.Device, "ether", state.MAC); err != nil {
		return fmt.Errorf("set the address of %s: %w", state.Device, err)
	}
	if err := p.filterPort(ctx, state); err != nil {
		return err
	}
	if _, err := p.manager.RunIfconfig(ctx, state.Device, "vnet", namespace); err != nil {
		return fmt.Errorf("move %s into jail %q: %w", state.Device, namespace, err)
	}
	configure := []string{"-j", namespace, state.Device}
	if state.IfName != state.Device {
		configure = append(configure, "name", state.IfName)
	}
	if mtu > 0 {
		configure = append(configure, "mtu", strconv.Itoa(mtu))
	}
	configure = append(configure, "up")
	if _, err := p.manager.RunIfconfig(ctx, configure...); err != nil {
		return fmt.Errorf("configure %s in jail %q: %w", state.IfName, namespace, err)
	}
	for _, address := range state.Addresses {
		if _, err := p.manager.RunIfconfig(ctx, "-j", namespace, state.IfName, "inet", address.IPNet, "alias"); err != nil && !alreadyThere(err) {
			return fmt.Errorf("set the address %s of %s in jail %q: %w", address.IPNet, state.IfName, namespace, err)
		}
	}
	for _, wanted := range routesOf(state.Addresses, routes) {
		if err := p.addRoute(ctx, namespace, state.IfName, wanted.destination, wanted.gateway); err != nil {
			return err
		}
	}
	if state.NatTable == "" {
		return nil
	}
	for _, address := range state.Addresses {
		if _, err := p.run(ctx, "pfctl", "-t", state.NatTable, "-T", "add", bareAddress(address.IPNet)); err != nil {
			return fmt.Errorf("add %s to the pf table %q: %w", bareAddress(address.IPNet), state.NatTable, err)
		}
	}
	return nil
}

// filterPort stops the container from sending with a MAC or an address that is
// not its own, and everything but the traffic meant for it from reaching it.
func (p *plugin) filterPort(ctx context.Context, state State) error {
	rule := guard.Rule{
		JailMAC:   state.MAC,
		BridgeMAC: p.bridgeMAC(ctx, state.Bridge),
		Addresses: guardAddresses(state.Addresses),
	}
	in, err := cbpf.Parse(rule.In())
	if err != nil {
		return fmt.Errorf("incoming filter: %w", err)
	}
	out, err := cbpf.Parse(rule.Out())
	if err != nil {
		return fmt.Errorf("outgoing filter: %w", err)
	}
	if _, err := p.manager.SetFilter(ctx, state.Bridge, state.Port, in, out); err != nil {
		return fmt.Errorf("filter port %s of bridge %q: %w", state.Port, state.Bridge, err)
	}
	return nil
}

// bridgeMAC reports the address of the bridge interface, empty when it cannot be
// read, which leaves the filter unpinned at that end.
func (p *plugin) bridgeMAC(ctx context.Context, name string) string {
	status, err := p.manager.RunIfconfig(ctx, name)
	if err != nil {
		return ""
	}
	fields := strings.Fields(status)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "ether" {
			continue
		}
		if address, err := net.ParseMAC(fields[i+1]); err == nil {
			return address.String()
		}
	}
	return ""
}

// guardAddresses reports the addresses of a container the way the filters want
// them.
func guardAddresses(addresses []netAddress) []guard.Address {
	guarded := make([]guard.Address, 0, len(addresses))
	for _, address := range addresses {
		guarded = append(guarded, guard.Address{
			Address: bareAddress(address.IPNet),
			Gateway: address.Gateway,
		})
	}
	return guarded
}

// teardownState removes the port of one network of one container, takes its
// addresses out of the masquerading table and forgets the state.
func (p *plugin) teardownState(ctx context.Context, state State) error {
	errs := []error{}
	if state.NatTable != "" {
		for _, address := range state.Addresses {
			if _, err := p.run(ctx, "pfctl", "-t", state.NatTable, "-T", "delete", bareAddress(address.IPNet)); err != nil && !alreadyThere(err) {
				errs = append(errs, fmt.Errorf("remove %s from the pf table %q: %w", bareAddress(address.IPNet), state.NatTable, err))
			}
		}
	}
	if err := p.manager.DestroyPort(ctx, state.Bridge, state.Port); err != nil && !errors.Is(err, bridge.ErrNotFound) {
		errs = append(errs, fmt.Errorf("remove the port %s of bridge %q: %w", state.Port, state.Bridge, err))
	}
	if err := removeState(p.configDir, state.Network, state.Container); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// wantedRoute is one route a container gets.
type wantedRoute struct {
	destination string
	gateway     string
}

// routesOf collects the routes a container gets from the gateways of its
// addresses and from the routes of the network, dropping duplicates.
func routesOf(addresses []netAddress, routes []route) []wantedRoute {
	wanted := []wantedRoute{}
	seen := map[wantedRoute]bool{}
	add := func(destination, gateway string) {
		route := wantedRoute{destination: destination, gateway: gateway}
		if seen[route] {
			return
		}
		seen[route] = true
		wanted = append(wanted, route)
	}
	for _, address := range addresses {
		if address.Gateway != "" {
			add("0.0.0.0/0", address.Gateway)
		}
	}
	for _, route := range routes {
		add(route.Destination, route.Gateway)
	}
	return wanted
}

// addRoute makes one route of a container authoritative: a route that is
// already there is changed instead of added, since a container whose loopback
// carries a default route starts with one that this command has to replace.
func (p *plugin) addRoute(ctx context.Context, namespace, ifName, destination, gateway string) error {
	args := []string{"-j", namespace, "add", "-4"}
	if isDefaultRoute(destination) {
		args = append(args, "default")
	} else {
		args = append(args, "-net", destination)
	}
	if gateway != "" {
		args = append(args, gateway)
	} else {
		args = append(args, "-interface", ifName)
	}
	if _, err := p.run(ctx, "route", args...); err == nil {
		return nil
	} else if !alreadyThere(err) {
		return fmt.Errorf("add the route %q in jail %q: %w", strings.Join(args[3:], " "), namespace, err)
	}
	args[2] = "change"
	if _, err := p.run(ctx, "route", args...); err != nil && !alreadyThere(err) {
		return fmt.Errorf("change the route %q in jail %q: %w", strings.Join(args[3:], " "), namespace, err)
	}
	return nil
}

// isDefaultRoute reports whether destination names the route every other route
// falls back to.
func isDefaultRoute(destination string) bool {
	switch destination {
	case "", "default", "0.0.0.0/0", "0/0":
		return true
	}
	return false
}

// addressesOf matches the addresses podman allocated with the subnets of the
// network, which is what the container gets on its interface.
func addressesOf(subnets []subnet, ips []string) ([]netAddress, error) {
	parsed := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		address := net.ParseIP(ip)
		if address == nil {
			return nil, fmt.Errorf("%q is not an address", ip)
		}
		if address.To4() == nil {
			return nil, fmt.Errorf("address %q: IPv6 is not implemented", ip)
		}
		parsed = append(parsed, address)
	}
	addresses := []netAddress{}
	for _, subnet := range subnets {
		_, network, err := net.ParseCIDR(subnet.Subnet)
		if err != nil {
			return nil, fmt.Errorf("subnet %q: %w", subnet.Subnet, err)
		}
		if network.IP.To4() == nil {
			continue
		}
		ones, _ := network.Mask.Size()
		for _, address := range parsed {
			if !network.Contains(address) {
				continue
			}
			addresses = append(addresses, netAddress{
				IPNet:   fmt.Sprintf("%s/%d", address, ones),
				Gateway: subnet.Gateway,
			})
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("no IPv4 address of the container is in a subnet of the network")
	}
	return addresses, nil
}

// natTableOf reports the pf table the addresses of a network's containers are
// entered in, empty when they are not masqueraded. A network that names a table
// uses that one, an internal network and a network that names the empty table
// are not masqueraded, and everything else uses defaultNatTable.
func natTableOf(network network) string {
	if table, named := network.Options[natTableOption]; named {
		return table
	}
	if network.Internal {
		return ""
	}
	return defaultNatTable
}

// mtuOf reports the MTU a network asks for, zero when it asks for none.
func mtuOf(network network) (int, error) {
	value := network.Options[mtuOption]
	if value == "" {
		return 0, nil
	}
	mtu, err := strconv.Atoi(value)
	if err != nil || mtu <= 0 {
		return 0, fmt.Errorf("option %q is %q, not an MTU", mtuOption, value)
	}
	return mtu, nil
}

// bareAddress reports an address without the prefix length it is written with.
func bareAddress(value string) string {
	address, _, _ := strings.Cut(value, "/")
	return address
}

// hasAddress reports whether ifconfig output names address.
func hasAddress(status, address string) bool {
	fields := strings.Fields(status)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "inet" {
			continue
		}
		if bareAddress(fields[i+1]) == address {
			return true
		}
	}
	return false
}

// alreadyThere recognises the errors ifconfig, route and pfctl report for
// something that is already in the state a command wanted to put it in.
func alreadyThere(err error) bool {
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"exist", "already", "file exists"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// run executes a command through the same runner the netgraph commands go
// through.
func (p *plugin) run(ctx context.Context, name string, args ...string) (string, error) {
	runner := p.manager.Ng.Runner
	if runner == nil {
		runner = ngctl.ExecRunner{}
	}
	out, err := runner.Run(ctx, name, args...)
	return string(out), err
}
