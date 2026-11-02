// Package netavark implements what podman asks of the netavark(1) command on
// FreeBSD: connecting a jail to a netgraph bridge, the way netavark's bridge
// driver connects a Linux network namespace to a bridge.
//
// Only the bridge driver is implemented. Podman allocates the addresses of a
// container itself and hands them over as static addresses, so there is no IPAM
// here, and DNS is left to the host, because aardvark-dns is Linux only. Port
// mappings (pf redirection) are not implemented either.
package netavark

import (
	"bytes"
	"encoding/json"
	"errors"
)

// request is what podman writes to the standard input of the command: the
// network options of one container, with the definitions of the networks it is
// connected to appended under "network_info".
type request struct {
	ContainerID string             `json:"container_id"`
	Networks    networks           `json:"networks"`
	NetworkInfo map[string]network `json:"network_info"`
}

// networks is what the request says about the networks of one container, by
// network name.
type networks map[string]perNetworkOptions

// UnmarshalJSON implements json.Unmarshaler. Podman up to 5.x sends the
// networks as a map keyed by network name, later versions send a list of named
// options, which keeps the order the networks were connected in. Both are
// taken, so that one binary works with either.
func (n *networks) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		list := []perNetworkOptions{}
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		networks := make(map[string]perNetworkOptions, len(list))
		for _, options := range list {
			if options.Name == "" {
				return errors.New("a network of the request has no name")
			}
			name := options.Name
			options.Name = ""
			networks[name] = options
		}
		*n = networks
		return nil
	}
	object := map[string]perNetworkOptions{}
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return err
	}
	*n = object
	return nil
}

// perNetworkOptions is what one network hands to a container.
type perNetworkOptions struct {
	// Name is the name of the network, which the list form of the request
	// carries instead of the key of the map form.
	Name string `json:"name,omitempty"`
	// StaticIPs are the addresses podman allocated for this network.
	StaticIPs []string `json:"static_ips,omitempty"`
	// StaticMAC is the address of the container interface, empty to derive one
	// from the network name and the container id.
	StaticMAC string `json:"static_mac,omitempty"`
	// InterfaceName is the name of the interface inside the jail.
	InterfaceName string `json:"interface_name"`
}

// network is the definition of one network, as podman stored it.
type network struct {
	// Driver is the network driver, "bridge" for the networks this command
	// implements.
	Driver string `json:"driver"`
	// NetworkInterface is the name of the bridge interface on the host.
	NetworkInterface string `json:"network_interface,omitempty"`
	// Subnets are the subnets of the network with their gateways.
	Subnets []subnet `json:"subnets,omitempty"`
	// Routes are routes every container of the network gets.
	Routes []route `json:"routes,omitempty"`
	// Internal marks a network that is only reachable from its own containers,
	// which is not masqueraded.
	Internal bool `json:"internal"`
	// Options are the driver options, "nat_table" and "mtu" are understood.
	Options map[string]string `json:"options,omitempty"`
}

// subnet is one subnet of a network.
type subnet struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway,omitempty"`
}

// route is one route every container of a network gets.
type route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
}

// statusBlock is what netavark reports per network: the interfaces the container
// got and, when a resolver serves the network, what to resolve against. Podman
// keeps it as the network status of the container.
type statusBlock struct {
	Interfaces       map[string]netInterface `json:"interfaces,omitempty"`
	DNSServerIPs     []string                `json:"dns_server_ips,omitempty"`
	DNSSearchDomains []string                `json:"dns_search_domains,omitempty"`
}

// netInterface is one interface the container got.
type netInterface struct {
	Subnets    []netAddress `json:"subnets,omitempty"`
	MacAddress string       `json:"mac_address"`
}

// netAddress is one address of the container, with the subnet it comes from and
// the gateway of that subnet.
type netAddress struct {
	IPNet   string `json:"ipnet"`
	Gateway string `json:"gateway,omitempty"`
}
