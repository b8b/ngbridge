package netavark

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// homeLocalIPAM is the address driver whose addresses podman allocates
	// itself, which is the only one that makes sense here.
	homeLocalIPAM = "host-local"
	// ipamNone turns address allocation off, for a network that only routes
	// traffic between its own containers.
	ipamNone = "none"
)

// namePattern is what a network name may look like, and driverPattern what the
// interface of a network may look like.
var (
	namePattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
)

// create works out the network podman asked for and reports it in the form
// podman stores it: it fills in the parts netavark fills in as well, which is
// the bridge interface, a subnet out of the subnets pools when none was given,
// the gateways of the subnets and the address driver.
func (p *plugin) create(req *createRequest) (*network, error) {
	network := req.Network
	if err := validateNetwork(&network, req.Used); err != nil {
		return nil, err
	}
	if network.Driver == "" {
		network.Driver = bridgeDriver
	}
	if network.Driver != bridgeDriver {
		return nil, fmt.Errorf("network driver %q is not implemented, only %q is", network.Driver, bridgeDriver)
	}
	if network.IPv6Enabled {
		return nil, errors.New("IPv6 is not implemented")
	}
	if err := dockerOptions(&network); err != nil {
		return nil, err
	}
	ipamDriver, err := ipamDriverOf(network)
	if err != nil {
		return nil, err
	}
	if ipamDriver == ipamNone {
		network.DNSEnabled = false
	}
	if err := nameInterface(&network, req); err != nil {
		return nil, err
	}
	if ipamDriver == homeLocalIPAM {
		if len(network.Subnets) == 0 {
			free, err := freeSubnet(req.Options.SubnetPools, req.Used.Subnets, req.Options.CheckUsedSubnets)
			if err != nil {
				return nil, err
			}
			network.Subnets = []subnet{free}
		}
		network.IPAMOptions = map[string]string{"driver": homeLocalIPAM}
	}
	if err := putGateways(&network); err != nil {
		return nil, err
	}
	network.Created = time.Now().UTC().Format(time.RFC3339)
	return &network, nil
}

// validateNetwork reports what is wrong with the network podman wants to create.
func validateNetwork(network *network, used usedNetworks) error {
	if network.Name == "" {
		return errors.New("the network has no name")
	}
	if !namePattern.MatchString(network.Name) {
		return fmt.Errorf("invalid characters in network name %q: must match [a-zA-Z0-9][a-zA-Z0-9_.-]*", network.Name)
	}
	if _, exists := used.Names[network.Name]; exists {
		return fmt.Errorf("network already exists %s", network.Name)
	}
	if network.ID == "" {
		return errors.New("the network has no id")
	}
	if len(network.ID) != 64 {
		return fmt.Errorf("network id %q is not 64 characters long", network.ID)
	}
	if _, err := hex.DecodeString(network.ID); err != nil {
		return fmt.Errorf("network id %q is not a hexadecimal string: %w", network.ID, err)
	}
	return nil
}

// dockerOptions turns the docker compatibility options into the ones this
// command uses, the way netavark does.
func dockerOptions(network *network) error {
	for from, to := range map[string]string{
		"com.docker.network.driver.mtu":  mtuOption,
		"com.docker.network.bridge.name": "",
	} {
		value, ok := network.Options[from]
		if !ok {
			continue
		}
		delete(network.Options, from)
		if to == "" {
			network.NetworkInterface = value
			continue
		}
		if network.Options == nil {
			network.Options = map[string]string{}
		}
		network.Options[to] = value
	}
	if mtu := network.Options[mtuOption]; mtu != "" {
		if _, err := mtuOf(*network); err != nil {
			return err
		}
	}
	return nil
}

// ipamDriverOf reports the address driver of the network, which is host-local
// when none was asked for.
func ipamDriverOf(network network) (string, error) {
	driver := network.IPAMOptions["driver"]
	switch driver {
	case "", homeLocalIPAM:
		return homeLocalIPAM, nil
	case ipamNone:
		if len(network.Subnets) > 0 {
			return "", errors.New("the address driver is none, but subnets are given")
		}
		return ipamNone, nil
	}
	return "", fmt.Errorf("address driver %q is not implemented, only %q and %q are", driver, homeLocalIPAM, ipamNone)
}

// nameInterface keeps the bridge interface the network names, or picks the first
// free one below the default name.
func nameInterface(network *network, req *createRequest) error {
	if network.NetworkInterface != "" {
		if err := validateInterfaceName(network.NetworkInterface); err != nil {
			return err
		}
		for _, used := range req.Used.Interfaces {
			if used == network.NetworkInterface {
				return fmt.Errorf("bridge name %s already in use", network.NetworkInterface)
			}
		}
		return nil
	}
	prefix := req.Options.DefaultInterfaceName
	if prefix == "" {
		return errors.New("no default interface name is set")
	}
	inUse := map[string]bool{}
	for _, used := range req.Used.Interfaces {
		inUse[used] = true
	}
	for name := range req.Used.Names {
		inUse[name] = true
	}
	for index := 1; ; index++ {
		name := prefix + strconv.Itoa(index)
		if inUse[name] {
			continue
		}
		if err := validateInterfaceName(name); err != nil {
			return err
		}
		network.NetworkInterface = name
		return nil
	}
}

// validateInterfaceName reports what is wrong with a bridge interface name.
func validateInterfaceName(name string) error {
	switch {
	case len(name) > 15:
		return fmt.Errorf("interface name %q is longer than 15 characters", name)
	case name == "." || name == "..":
		return fmt.Errorf("interface name %q is not a name", name)
	case strings.ContainsAny(name, "/: \t\n"):
		return fmt.Errorf("interface name %q contains a character that is not allowed", name)
	case !interfacePattern.MatchString(name):
		return fmt.Errorf("invalid characters in interface name %q: must match [a-zA-Z0-9][a-zA-Z0-9_.-]*", name)
	}
	return nil
}

// putGateways puts the first address of each subnet on it as the gateway, for a
// network that has one, and checks that a gateway that was given is inside its
// subnet.
func putGateways(network *network) error {
	addGateway := !network.Internal || network.DNSEnabled
	for index := range network.Subnets {
		entry := &network.Subnets[index]
		address, parsed, err := net.ParseCIDR(entry.Subnet)
		if err != nil {
			return fmt.Errorf("subnet %q: %w", entry.Subnet, err)
		}
		if address.To4() == nil {
			return fmt.Errorf("subnet %q: IPv6 is not implemented", entry.Subnet)
		}
		ones, bits := parsed.Mask.Size()
		if ones > bits-2 {
			return fmt.Errorf("subnet %q is too small for a gateway", entry.Subnet)
		}
		if entry.Gateway != "" {
			gateway := net.ParseIP(entry.Gateway)
			if gateway == nil || !parsed.Contains(gateway) {
				return fmt.Errorf("gateway %q is not in subnet %q", entry.Gateway, entry.Subnet)
			}
			continue
		}
		if !addGateway {
			continue
		}
		first := make(net.IP, len(parsed.IP.To4()))
		copy(first, parsed.IP.To4())
		first[len(first)-1]++
		entry.Gateway = first.String()
	}
	if len(network.Subnets) == 0 && network.IPAMOptions["driver"] != ipamNone {
		return errors.New("the network has no subnet")
	}
	return nil
}

// freeSubnet reports the first subnet of the pools that is not in use, of the
// size the pool asks for.
func freeSubnet(pools []subnetPool, used []string, check bool) (subnet, error) {
	usedNetworks := make([]*net.IPNet, 0, len(used))
	for _, cidr := range used {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return subnet{}, fmt.Errorf("subnet in use %q: %w", cidr, err)
		}
		usedNetworks = append(usedNetworks, network)
	}
	for _, pool := range pools {
		base, network, err := net.ParseCIDR(pool.Base)
		if err != nil {
			return subnet{}, fmt.Errorf("subnet pool %q: %w", pool.Base, err)
		}
		if base.To4() == nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if pool.Size < 1 || pool.Size > bits {
			return subnet{}, fmt.Errorf("subnet pool %q: size %d is not a prefix length", pool.Base, pool.Size)
		}
		if pool.Size < ones {
			return subnet{}, fmt.Errorf("subnet pool %q: size %d is smaller than the pool", pool.Base, pool.Size)
		}
		mask := net.CIDRMask(pool.Size, bits)
		first := uint64(binary.BigEndian.Uint32(network.IP.To4()))
		limit := first + uint64(1)<<(bits-ones)
		for address := first; address < limit; address += uint64(1) << (bits - pool.Size) {
			candidate := &net.IPNet{IP: addressOf(uint32(address)), Mask: mask}
			if !check || !overlapsAny(candidate, usedNetworks) {
				return subnet{Subnet: candidate.String()}, nil
			}
		}
	}
	return subnet{}, errors.New("no free subnet is left in the subnet pools")
}

// overlapsAny reports whether network overlaps one of the others.
func overlapsAny(network *net.IPNet, others []*net.IPNet) bool {
	for _, other := range others {
		if network.Contains(other.IP) || other.Contains(network.IP) {
			return true
		}
	}
	return false
}

// addressOf reports the IPv4 address with the given number.
func addressOf(value uint32) net.IP {
	address := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(address, value)
	return address
}
