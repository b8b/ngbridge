package cni

import (
	"fmt"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
)

// defaultNatTable is the pf table a masquerading rule is expected to match.
const defaultNatTable = "cni-nat"

// Config is the network configuration of this plugin.
type Config struct {
	types.NetConf
	// Bridge is the netgraph bridge to attach ports to. It is created when it
	// does not exist yet.
	Bridge string `json:"bridge"`
	// MTU of the container interface, zero to take the MTU of the bridge
	// interface.
	MTU int `json:"mtu"`
	// MAC of the container interface, empty to derive one from the network name
	// and the container id.
	MAC string `json:"mac"`
	// IP of the container, when the caller already knows it. Otherwise the
	// plugin takes the address from the IPAM plugin or from the jail, and only
	// filters the MAC until one of them has one.
	IP string `json:"ip"`
	// IsGateway is accepted for compatibility with the bridge plugin, but not
	// needed: a gateway the IPAM result names is always put on the bridge
	// interface, because the containers cannot route without it.
	IsGateway bool `json:"isGateway"`
	// IsForceGateway makes the containers reach everything through the gateway:
	// their addresses get a /32 prefix with explicit routes, and the filters only
	// allow traffic to and from the gateway.
	IsForceGateway bool `json:"isForceGateway"`
	// IsRestrictMulticast limits multicast to the multicast routes of the IPAM
	// result instead of allowing it as a whole.
	IsRestrictMulticast bool `json:"isRestrictMulticast"`
	// IPMasq enters the addresses of the containers in the pf table named by
	// NatTable, which is what a masquerading rule on the host matches against.
	IPMasq bool `json:"ipMasq"`
	// NatTable is the pf table of that rule, "cni-nat" when IPMasq is set and
	// this is empty.
	NatTable string `json:"natTable"`
	// ValidAttachments is what a GC invocation names as the attachments that
	// are still there. It is a pointer so that a configuration without the key
	// can be told from an empty list, which means nothing is valid any more.
	ValidAttachments *[]Attachment `json:"cni.dev/valid-attachments"`
	// HairpinMode is part of the configuration the bridge plugin used to accept.
	// It is taken but not implemented, because ng_bridge(4) has no hairpin mode.
	HairpinMode bool `json:"hairpinMode"`
}

// Validate reports what the configuration is missing.
func (c *Config) Validate() error {
	if c.NetConf.Name == "" {
		return fmt.Errorf("the network configuration has no name")
	}
	if c.Bridge == "" {
		return fmt.Errorf("the network configuration of %q has no bridge", c.NetConf.Name)
	}
	return nil
}

// natTable reports the pf table container addresses are entered in, empty when
// masquerading is not asked for.
func (c *Config) natTable() string {
	if c.NatTable != "" {
		return c.NatTable
	}
	if c.IPMasq {
		return defaultNatTable
	}
	return ""
}

// addressInfo is one address of the container, as the IPAM result names it. In
// force gateway mode Network is the subnet the address comes from, which the
// container reaches through the gateway.
type addressInfo struct {
	Address string
	Gateway string
	Network string
}

// inExpression is the filter for the frames that arrive from the container.
//
// Without an address only the addresses of the two ends are pinned, which
// leaves the container able to talk to the host interface and nothing else.
// With addresses, the source MAC has to be the container's and the source
// address one of its own, "src host" covering the ARP sender as well:
//
//	ether src <jail> and (src host <address> or src host <address>)
//
// With IsForceGateway the destination has to be the host interface or the
// gateway address, which is also what lets the container resolve the gateway
// with ARP, and with IsRestrictMulticast broadcast and unicast are allowed while
// multicast is limited to the networks of the IPAM result.
//
// The filters are built from the lists they are given, so a list that is empty
// leaves its clause out instead of contributing a constant that never matches.
func (c *Config) inExpression(jailMAC, hostMAC string, addresses []addressInfo, multicast []string) string {
	if len(addresses) == 0 {
		return andGroup([]string{"ether src " + jailMAC, pinnedTo(hostMAC)})
	}
	sources := []string{}
	for _, address := range addresses {
		sources = append(sources, "src host "+address.Address)
	}
	expression := "ether src " + jailMAC + " and " + group(sources)
	switch {
	case c.IsForceGateway:
		destinations := []string{pinnedTo(hostMAC)}
		seen := map[string]bool{}
		for _, address := range addresses {
			if address.Gateway == "" || seen[address.Gateway] {
				continue
			}
			seen[address.Gateway] = true
			destinations = append(destinations, "dst host "+address.Gateway)
		}
		if allowed := group(destinations); allowed != "" {
			expression += " and " + allowed
		}
	case c.IsRestrictMulticast:
		allowed := []string{"ether broadcast", "not ether multicast"}
		for _, network := range multicast {
			allowed = append(allowed, "dst net "+network)
		}
		expression += " and " + group(allowed)
	}
	return expression
}

// outExpression is the filter for the frames that go to the container.
//
// Once an address is known this is not a pin but a list of alternatives: frames
// from the bridge interface, frames for one of the container addresses, and
// multicast unless it is restricted to the networks of the IPAM result.
//
//	(ether src <bridge> or dst host <address> or ip multicast)
//
// The addresses are not pinned to the bridge interface on purpose: another
// container sends with its own MAC, and containers are allowed to talk to each
// other unless IsForceGateway makes them go through the gateway.
func (c *Config) outExpression(jailMAC, hostMAC string, addresses []addressInfo, multicast []string) string {
	if len(addresses) == 0 {
		return andGroup([]string{pinnedFrom(hostMAC), "ether dst " + jailMAC})
	}
	allowed := []string{pinnedFrom(hostMAC)}
	for _, address := range addresses {
		allowed = append(allowed, "dst host "+address.Address)
	}
	if c.IsRestrictMulticast {
		for _, network := range multicast {
			allowed = append(allowed, "dst net "+network)
		}
	} else {
		allowed = append(allowed, "ip multicast")
	}
	return group(allowed)
}

// pinnedTo and pinnedFrom report the clauses that pin the other end of a port
// to the address of the bridge interface, empty when it is not known.
func pinnedTo(hostMAC string) string {
	if hostMAC == "" {
		return ""
	}
	return "ether dst " + hostMAC
}

func pinnedFrom(hostMAC string) string {
	if hostMAC == "" {
		return ""
	}
	return "ether src " + hostMAC
}

// andGroup joins the clauses with "and", leaving the empty ones out.
func andGroup(clauses []string) string {
	parts := make([]string, 0, len(clauses))
	for _, clause := range clauses {
		if clause != "" {
			parts = append(parts, clause)
		}
	}
	return strings.Join(parts, " and ")
}

// group joins the clauses with "or" and brackets them when there is more than
// one. An empty list contributes nothing at all.
func group(clauses []string) string {
	parts := make([]string, 0, len(clauses))
	for _, clause := range clauses {
		if clause != "" {
			parts = append(parts, clause)
		}
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// Attachment is one attachment a GC invocation reports as still valid.
type Attachment struct {
	ContainerID string `json:"containerID"`
	IfName      string `json:"ifname"`
}
