package cni

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	current "github.com/containernetworking/cni/pkg/types/100"

	"github.com/containernetworking/cni/pkg/types"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
	"github.com/b8b/libjail/ngbridge/internal/cbpf"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
)

// Request is one invocation of the plugin: the configuration as the runtime
// sent it, what the runtime put in the environment and the container interface
// the invocation is about.
type Request struct {
	Config      *Config
	ContainerID string
	IfName      string
	NetNS       string
	Args        string
	// Path is CNI_PATH, the directories the IPAM plugin is looked up in.
	Path string
	// Raw is the configuration as it came in, which the IPAM plugin gets to see
	// unchanged.
	Raw []byte
}

// Plugin is the CNI plugin for one netgraph bridge.
type Plugin struct {
	// Manager drives netgraph and ifconfig.
	Manager *bridge.Manager
	// StateDir is the directory the state files live in, defaultStateDir when
	// empty.
	StateDir string
}

func (p *Plugin) stateDir() string {
	if p.StateDir == "" {
		return defaultStateDir
	}
	return p.StateDir
}

// Add attaches the container interface to the bridge, moves it into the jail
// and reports it. Calling it again for the same container interface tightens
// the filters when the container address is known by then, which is how the
// second pass after IPAM works.
func (p *Plugin) Add(ctx context.Context, req Request) (*current.Result, error) {
	conf, container, ifName := req.Config, req.ContainerID, req.IfName
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	addresses, err := p.ipam(ctx, req, "ADD")
	if err != nil {
		return nil, err
	}
	// The address is given back when anything after this point fails, so that a
	// failed ADD does not leak it.
	added := false
	defer func() {
		if !added {
			p.releaseIPAM(ctx, req)
		}
	}()
	if err := p.ensureBridge(ctx, conf); err != nil {
		return nil, err
	}
	if err := p.configureGateway(ctx, conf, addresses); err != nil {
		return nil, err
	}
	mac, err := conf.macAddress(container)
	if err != nil {
		return nil, err
	}
	state, exists, err := loadState(p.stateDir(), conf.Name, container, ifName)
	if err != nil {
		return nil, err
	}
	if exists {
		if p.portWithDevice(ctx, state) {
			state, err = p.configure(ctx, conf, state, mac, addresses)
			if err != nil {
				return nil, err
			}
			if err := saveState(p.stateDir(), state); err != nil {
				return nil, fmt.Errorf("save the state of %s: %w", ifName, err)
			}
			added = true
			return result(ifName, state, addresses), nil
		}
		if err := p.Manager.DestroyPort(ctx, state.Bridge, state.Port); err != nil &&
			!errors.Is(err, bridge.ErrNotFound) {
			return nil, fmt.Errorf("remove the stale port %s of bridge %q: %w", state.Port, state.Bridge, err)
		}
	}
	port, err := p.Manager.CreatePort(ctx, conf.Bridge, 0)
	if err != nil {
		return nil, fmt.Errorf("create port on bridge %q: %w", conf.Bridge, err)
	}
	state = State{
		Network: conf.Name, Container: container, IfName: ifName,
		Bridge: conf.Bridge, Port: port.Number(), Device: port.Interface, MAC: mac,
	}
	if state.Device == "" {
		state.Device = port.Name
	}
	state, err = p.configure(ctx, conf, state, mac, addresses)
	if err != nil {
		_ = p.Manager.DestroyPort(ctx, conf.Bridge, port.Number())
		return nil, err
	}
	if err := saveState(p.stateDir(), state); err != nil {
		_ = p.Manager.DestroyPort(ctx, conf.Bridge, port.Number())
		return nil, fmt.Errorf("save the state of %s: %w", ifName, err)
	}
	added = true
	return result(ifName, state, addresses), nil
}

// releaseIPAM gives an address back when the rest of the invocation failed.
func (p *Plugin) releaseIPAM(ctx context.Context, req Request) {
	_, _ = p.ipam(ctx, req, "DEL")
}

// Del removes the port of a container interface. It succeeds when there is
// nothing left to remove, which is what a repeated DEL looks like.
func (p *Plugin) Del(ctx context.Context, req Request) error {
	conf, container, ifName := req.Config, req.ContainerID, req.IfName
	if err := conf.Validate(); err != nil {
		return err
	}
	state, exists, err := loadState(p.stateDir(), conf.Name, container, ifName)
	if err != nil {
		return err
	}
	if !exists {
		return p.removeIPAM(ctx, req)
	}
	err = p.Manager.DestroyPort(ctx, state.Bridge, state.Port)
	if err != nil && !errors.Is(err, bridge.ErrNotFound) {
		return fmt.Errorf("remove port %s of bridge %q: %w", state.Port, state.Bridge, err)
	}
	p.removeFromNatTable(ctx, conf, state)
	if err := p.removeIPAM(ctx, req); err != nil {
		return err
	}
	return removeState(p.stateDir(), conf.Name, container, ifName)
}

// Check reports whether the container interface is still the one the state
// file describes.
func (p *Plugin) Check(ctx context.Context, req Request) error {
	conf, container, ifName := req.Config, req.ContainerID, req.IfName
	if err := conf.Validate(); err != nil {
		return err
	}
	if err := p.checkIPAM(ctx, req); err != nil {
		return err
	}
	state, exists, err := loadState(p.stateDir(), conf.Name, container, ifName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no state for %s in network %q", ifName, conf.Name)
	}
	if !p.portWithDevice(ctx, state) {
		return fmt.Errorf("port %s of bridge %q is gone", state.Port, state.Bridge)
	}
	filters, err := p.Manager.Filters(ctx, state.Bridge, state.Port)
	if err != nil {
		return err
	}
	if len(filters) == 0 {
		return fmt.Errorf("port %s of bridge %q has no filter", state.Port, state.Bridge)
	}
	return nil
}

// configureGateway puts the gateway address of the IPAM result on the bridge
// interface, so that the container default route has something to resolve. The
// address is only added when it is not there yet.
func (p *Plugin) configureGateway(ctx context.Context, conf *Config, addresses *current.Result) error {
	if addresses == nil {
		return nil
	}
	for _, config := range addresses.IPs {
		if config.Gateway == nil || config.Gateway.To4() == nil {
			continue
		}
		prefix, _ := config.Address.Mask.Size()
		wanted := fmt.Sprintf("%s/%d", config.Gateway, prefix)
		if status, err := p.Manager.RunIfconfig(ctx, conf.Bridge); err == nil {
			if strings.HasPrefix(parseAddress(status), config.Gateway.String()) {
				return nil
			}
		}
		if _, err := p.Manager.RunIfconfig(ctx, conf.Bridge, "inet", wanted); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "exist") {
			return fmt.Errorf("put the gateway %s on bridge %q: %w", wanted, conf.Bridge, err)
		}
		return nil
	}
	return nil
}

// ensureBridge creates the bridge when it does not exist yet, which several
// containers may do at the same time.
func (p *Plugin) ensureBridge(ctx context.Context, conf *Config) error {
	exists, err := p.Manager.Exists(ctx, conf.Bridge)
	if err != nil {
		return fmt.Errorf("look at bridge %q: %w", conf.Bridge, err)
	}
	if exists {
		if _, err := p.Manager.Get(ctx, conf.Bridge); err != nil {
			return err
		}
		return nil
	}
	if _, err := p.Manager.Create(ctx, conf.Bridge, "", true); err != nil &&
		!errors.Is(err, bridge.ErrExists) {
		return fmt.Errorf("create bridge %q: %w", conf.Bridge, err)
	}
	return nil
}

// portWithDevice reports whether the port the state file names is still there
// with the interface it was created with. A port whose interface is gone keeps
// its bridge hook and its filter, but it is not usable and is created again.
func (p *Plugin) portWithDevice(ctx context.Context, state State) bool {
	port, ok := p.portOf(ctx, state)
	return ok && port.Name == state.Device
}

// portOf reports the port of a state file, when the bridge still has it.
func (p *Plugin) portOf(ctx context.Context, state State) (bridge.Port, bool) {
	ports, err := p.Manager.Ports(ctx, state.Bridge)
	if err != nil {
		return bridge.Port{}, false
	}
	for _, port := range ports {
		if port.Number() == state.Port {
			return port, true
		}
	}
	return bridge.Port{}, false
}

// configure sets the address, the MTU and the filters of a port and moves the
// interface into the jail. It is the part Add repeats when the container
// address only becomes known later: once the interface is in the jail, only the
// filters are touched, which is how the second pass after IPAM tightens them.
func (p *Plugin) configure(ctx context.Context, conf *Config, state State, mac string, addresses *current.Result) (State, error) {
	device := state.Device
	if device == "" {
		return State{}, fmt.Errorf("port %s of bridge %q has no interface", state.Port, state.Bridge)
	}
	status, inJail := jailInterface(ctx, p.Manager, state.Container, state.IfName)
	ip := conf.IP
	if ip == "" {
		ip = addressOf(addresses)
	}
	if ip == "" {
		ip = parseAddress(status)
	}
	if !inJail {
		if _, err := p.Manager.RunIfconfig(ctx, device, "ether", mac); err != nil {
			return State{}, fmt.Errorf("set the address of %s: %w", device, err)
		}
	}
	infos := addressesOf(addresses)
	if len(infos) == 0 {
		if address := bareAddress(ip); address != "" {
			infos = []addressInfo{{Address: address}}
		}
	}
	hostMAC := p.hostMAC(ctx, conf.Bridge)
	in, err := cbpf.Parse(conf.inExpression(mac, hostMAC, infos, multicastOf(addresses)))
	if err != nil {
		return State{}, fmt.Errorf("incoming filter: %w", err)
	}
	out, err := cbpf.Parse(conf.outExpression(mac, hostMAC, infos, multicastOf(addresses)))
	if err != nil {
		return State{}, fmt.Errorf("outgoing filter: %w", err)
	}
	if _, err := p.Manager.SetFilter(ctx, conf.Bridge, state.Port, in, out); err != nil {
		return State{}, fmt.Errorf("filter port %s of bridge %q: %w", state.Port, conf.Bridge, err)
	}
	mtu := conf.MTU
	if mtu == 0 {
		mtu = p.Manager.InterfaceMTU(ctx, conf.Bridge)
	}
	state.MAC, state.IP, state.MTU = mac, ip, mtu
	if inJail {
		if err := p.configureContainer(ctx, conf, state, ip, addresses); err != nil {
			return State{}, err
		}
		return state, nil
	}
	if _, err := p.Manager.RunIfconfig(ctx, device, "vnet", state.Container); err != nil {
		return State{}, fmt.Errorf("move %s into jail %q: %w", device, state.Container, err)
	}
	configure := []string{"-j", state.Container, device}
	if state.IfName != device {
		configure = append(configure, "name", state.IfName)
	}
	if mtu > 0 {
		configure = append(configure, "mtu", strconv.Itoa(mtu))
	}
	configure = append(configure, "up")
	if _, err := p.Manager.RunIfconfig(ctx, configure...); err != nil {
		return State{}, fmt.Errorf("configure %s in jail %q: %w", state.IfName, state.Container, err)
	}
	if err := p.configureContainer(ctx, conf, state, ip, addresses); err != nil {
		return State{}, err
	}
	return state, nil
}

// jailInterface reports the ifconfig output for the container interface inside
// the jail, and whether the interface is there at all.
func jailInterface(ctx context.Context, manager *bridge.Manager, container, ifName string) (string, bool) {
	out, err := manager.RunIfconfig(ctx, "-j", container, ifName)
	if err != nil {
		return "", false
	}
	return out, true
}

// parseAddress reads the first IPv4 address out of ifconfig output, with the
// prefix length ifconfig prints next to it.
func parseAddress(out string) string {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "inet" {
			continue
		}
		value, _, _ := strings.Cut(fields[i+1], " ")
		address, _, _ := strings.Cut(value, "/")
		if net.ParseIP(address) != nil {
			return value
		}
	}
	return ""
}

// result reports the interface the container got, with the addresses the IPAM
// plugin handed out when there is one.
func result(ifName string, state State, addresses *current.Result) *current.Result {
	res := &current.Result{}
	interfaceResult := &current.Interface{Name: ifName}
	if mac, err := net.ParseMAC(state.MAC); err == nil {
		interfaceResult.Mac = mac.String()
	}
	res.Interfaces = append(res.Interfaces, interfaceResult)
	if addresses != nil {
		for _, config := range addresses.IPs {
			config.Interface = current.Int(0)
			res.IPs = append(res.IPs, config)
		}
		res.Routes = append(res.Routes, addresses.Routes...)
		res.DNS = addresses.DNS
		return res
	}
	if state.IP != "" {
		if address, network, err := net.ParseCIDR(state.IP); err == nil {
			network.IP = address
			res.IPs = append(res.IPs, &current.IPConfig{Address: *network, Interface: current.Int(0)})
		} else if address := net.ParseIP(state.IP); address != nil {
			res.IPs = append(res.IPs, &current.IPConfig{
				Address:   net.IPNet{IP: address, Mask: net.CIDRMask(32, 32)},
				Interface: current.Int(0),
			})
		}
	}
	return res
}

// addressOf reports the container address of an IPAM result, preferring IPv4.
func addressOf(addresses *current.Result) string {
	if addresses == nil {
		return ""
	}
	for _, config := range addresses.IPs {
		if config.Address.IP.To4() != nil {
			return config.Address.String()
		}
	}
	if len(addresses.IPs) > 0 {
		return addresses.IPs[0].Address.String()
	}
	return ""
}

// macAddress reports the address the container interface gets.
func (c *Config) macAddress(container string) (string, error) {
	if c.MAC != "" {
		address, err := net.ParseMAC(c.MAC)
		if err != nil {
			return "", fmt.Errorf("mac %q: %w", c.MAC, err)
		}
		return address.String(), nil
	}
	return deriveMAC(c.Name, container)
}

// stateDirFromEnv reports the state directory, which the tests and unusual
// installations can point elsewhere.
func stateDirFromEnv() string {
	if dir := os.Getenv("NGBRIDGE_CNI_STATE_DIR"); dir != "" {
		return dir
	}
	return defaultStateDir
}

// hostMAC reports the address of the bridge interface, which is what the
// filters pin the other end to. It is empty when it cannot be read, and the
// filters then leave the other end open.
func (p *Plugin) hostMAC(ctx context.Context, bridge string) string {
	status, err := p.Manager.RunIfconfig(ctx, bridge)
	if err != nil {
		return ""
	}
	return parseMAC(status)
}

// bareAddress reports an address without its prefix length.
func bareAddress(value string) string {
	address, _, _ := strings.Cut(value, "/")
	return address
}

// parseMAC reads the first "ether <address>" out of ifconfig output.
func parseMAC(out string) string {
	fields := strings.Fields(out)
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

// addressesOf reports the IPv4 addresses of an IPAM result with their gateways.
func addressesOf(addresses *current.Result) []addressInfo {
	if addresses == nil {
		return nil
	}
	infos := []addressInfo{}
	for _, config := range addresses.IPs {
		if config.Address.IP.To4() == nil {
			continue
		}
		info := addressInfo{Address: config.Address.IP.String()}
		if config.Gateway != nil && config.Gateway.To4() != nil {
			info.Gateway = config.Gateway.String()
		}
		if ones, bits := config.Address.Mask.Size(); bits == 32 && ones < 32 {
			network := net.IPNet{IP: config.Address.IP.Mask(config.Address.Mask), Mask: config.Address.Mask}
			info.Network = network.String()
		}
		infos = append(infos, info)
	}
	return infos
}

// multicastOf reports the multicast networks of the routes of an IPAM result.
func multicastOf(addresses *current.Result) []string {
	if addresses == nil {
		return nil
	}
	networks := []string{}
	for _, route := range addresses.Routes {
		if !route.Dst.IP.IsMulticast() {
			continue
		}
		networks = append(networks, route.Dst.String())
	}
	return networks
}

// configureContainer puts the address of the container on the interface inside
// the jail, adds the routes and enters the address in the masquerading table.
// Everything it does is idempotent, so a repeated ADD is harmless.
//
// With IsForceGateway the container gets its address with a /32 prefix and
// explicit routes, so that everything it sends has to go through the gateway:
// a host route for the gateway over the interface and the networks of the IPAM
// result behind the gateway. Without it the address carries its real prefix and
// the routes are added as the IPAM result names them.
func (p *Plugin) configureContainer(ctx context.Context, conf *Config, state State, ip string, addresses *current.Result) error {
	if ip == "" {
		return nil
	}
	address := bareAddress(ip)
	ones := prefixOf(ip)
	if conf.IsForceGateway {
		ones = 32
	}
	if ones == 0 {
		ones = 32
	}
	if _, err := p.run(ctx, "ifconfig", "-j", state.Container, state.IfName, "inet",
		fmt.Sprintf("%s/%d", address, ones), "alias"); err != nil && !alreadyThere(err) {
		return fmt.Errorf("set the address %s/%d of %s in jail %q: %w", address, ones, state.IfName, state.Container, err)
	}
	gateway := gatewayOf(addresses)
	added := map[string]bool{}
	addRoute := func(args ...string) error {
		entry := strings.Join(args, " ")
		if added[entry] {
			return nil
		}
		added[entry] = true
		full := append([]string{"-j", state.Container, "add", "-4"}, args...)
		_, err := p.run(ctx, "route", full...)
		if err == nil {
			return nil
		}
		if !alreadyThere(err) {
			return fmt.Errorf("add the route %q in jail %q: %w", entry, state.Container, err)
		}
		// The route was there already, but it may point somewhere else, since a
		// container whose loopback was given a host route of 0.0.0.0/0 starts
		// with a default route that goes to the loopback. Changing it makes the
		// routes this plugin sets authoritative.
		change := append([]string{"-j", state.Container, "change", "-4"}, args...)
		if _, err := p.run(ctx, "route", change...); err != nil && !alreadyThere(err) {
			return fmt.Errorf("change the route %q in jail %q: %w", entry, state.Container, err)
		}
		return nil
	}
	if conf.IsForceGateway && gateway != "" {
		// The gateway has to be on the interface before a route can point at it.
		if err := addRoute("-host", gateway, "-interface", state.IfName); err != nil {
			return err
		}
	}
	for _, route := range routesOf(addresses) {
		if route.GW == nil && gateway != "" {
			route.GW = net.ParseIP(gateway)
		}
		switch {
		case route.GW != nil:
			if conf.IsForceGateway {
				if err := addRoute("-host", route.GW.String(), "-interface", state.IfName); err != nil {
					return err
				}
			}
			if err := addRoute("-net", route.Dst.String(), route.GW.String()); err != nil {
				return err
			}
		default:
			if err := addRoute("-net", route.Dst.String(), "-interface", state.IfName); err != nil {
				return err
			}
		}
	}
	if table := conf.natTable(); table != "" {
		if _, err := p.run(ctx, "pfctl", "-t", table, "-T", "add", address); err != nil {
			return fmt.Errorf("add %s to the pf table %q: %w", address, table, err)
		}
	}
	return nil
}

// prefixOf reports the prefix length of an address, zero when there is none.
func prefixOf(value string) int {
	_, prefix, found := strings.Cut(value, "/")
	if !found {
		return 0
	}
	ones, err := strconv.Atoi(prefix)
	if err != nil {
		return 0
	}
	return ones
}

// removeFromNatTable takes the container address out of the masquerading table.
func (p *Plugin) removeFromNatTable(ctx context.Context, conf *Config, state State) {
	table := conf.natTable()
	if table == "" || state.IP == "" {
		return
	}
	address, _, _ := strings.Cut(state.IP, "/")
	_, _ = p.run(ctx, "pfctl", "-t", table, "-T", "delete", address)
}

// run executes one of the interface programs the plugin needs.
func (p *Plugin) run(ctx context.Context, name string, args ...string) (string, error) {
	runner := p.Manager.Ng.Runner
	if runner == nil {
		runner = ngctl.ExecRunner{}
	}
	out, err := runner.Run(ctx, name, args...)
	return string(out), err
}

// alreadyThere recognises the errors that mean the work was done before.
func alreadyThere(err error) bool {
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"exist", "already", "file exists"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// gatewayOf reports the gateway address of an IPAM result.
func gatewayOf(addresses *current.Result) string {
	if addresses == nil {
		return ""
	}
	for _, config := range addresses.IPs {
		if config.Gateway != nil && config.Gateway.To4() != nil {
			return config.Gateway.String()
		}
	}
	return ""
}

// routesOf reports the routes of an IPAM result.
func routesOf(addresses *current.Result) []*types.Route {
	if addresses == nil {
		return nil
	}
	return addresses.Routes
}
