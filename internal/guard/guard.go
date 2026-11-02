// Package guard builds the pcap-style expressions that the ng_bpf(4) filters of
// a bridge port run: they stop a container from sending with a MAC or an
// address that is not its own, and stop everything but the traffic meant for it
// from reaching it.
package guard

import "strings"

// Address is one address of a container, with the gateway and the network it
// comes from.
type Address struct {
	Address string
	Gateway string
	Network string
}

// Rule is what the filters of one port are built from.
type Rule struct {
	// JailMAC is the address of the container interface.
	JailMAC string
	// BridgeMAC is the address of the bridge interface, empty when it is not
	// known.
	BridgeMAC string
	// Addresses are the addresses the container may use, empty while none is
	// known yet.
	Addresses []Address
	// ForceGateway makes the container reach everything through the gateway:
	// its addresses get a /32 prefix with explicit routes, and the filters only
	// allow traffic to and from the gateway.
	ForceGateway bool
	// RestrictMulticast limits multicast to the networks in Networks instead of
	// allowing it as a whole.
	RestrictMulticast bool
	// Networks are the multicast networks a restricted filter allows.
	Networks []string
}

// In is the filter for the frames that arrive from the container.
//
// Without an address only the addresses of the two ends are pinned, which
// leaves the container able to talk to the host interface and nothing else. With
// addresses, the source MAC has to be the container's and the source address one
// of its own, "src host" covering the ARP sender as well:
//
//	ether src <jail> and (src host <address> or src host <address>)
//
// With ForceGateway the destination has to be the host interface or the gateway
// address, which is also what lets the container resolve the gateway with ARP,
// and with RestrictMulticast broadcast and unicast are allowed while multicast
// is limited to the given networks.
//
// The filters are built from the lists they are given, so a list that is empty
// leaves its clause out instead of contributing a constant that never matches.
func (r Rule) In() string {
	if len(r.Addresses) == 0 {
		return andGroup([]string{"ether src " + r.JailMAC, pinnedTo(r.BridgeMAC)})
	}
	sources := []string{}
	for _, address := range r.Addresses {
		sources = append(sources, "src host "+address.Address)
	}
	expression := "ether src " + r.JailMAC + " and " + group(sources)
	switch {
	case r.ForceGateway:
		destinations := []string{pinnedTo(r.BridgeMAC)}
		seen := map[string]bool{}
		for _, address := range r.Addresses {
			if address.Gateway == "" || seen[address.Gateway] {
				continue
			}
			seen[address.Gateway] = true
			destinations = append(destinations, "dst host "+address.Gateway)
		}
		if allowed := group(destinations); allowed != "" {
			expression += " and " + allowed
		}
	case r.RestrictMulticast:
		allowed := []string{"ether broadcast", "not ether multicast"}
		for _, network := range r.Networks {
			allowed = append(allowed, "dst net "+network)
		}
		expression += " and " + group(allowed)
	}
	return expression
}

// Out is the filter for the frames that go to the container.
//
// Once an address is known this is not a pin but a list of alternatives: frames
// from the bridge interface, frames for one of the container addresses, and
// multicast unless it is restricted to the given networks.
//
//	(ether src <bridge> or dst host <address> or ip multicast)
//
// The addresses are not pinned to the bridge interface on purpose: another
// container sends with its own MAC, and containers are allowed to talk to each
// other unless ForceGateway makes them go through the gateway.
func (r Rule) Out() string {
	if len(r.Addresses) == 0 {
		return andGroup([]string{pinnedFrom(r.BridgeMAC), "ether dst " + r.JailMAC})
	}
	allowed := []string{pinnedFrom(r.BridgeMAC)}
	for _, address := range r.Addresses {
		allowed = append(allowed, "dst host "+address.Address)
	}
	if r.RestrictMulticast {
		for _, network := range r.Networks {
			allowed = append(allowed, "dst net "+network)
		}
	} else {
		allowed = append(allowed, "ip multicast")
	}
	return group(allowed)
}

// pinnedTo and pinnedFrom report the clauses that pin the other end of a port to
// the address of the bridge interface, empty when it is not known.
func pinnedTo(bridgeMAC string) string {
	if bridgeMAC == "" {
		return ""
	}
	return "ether dst " + bridgeMAC
}

func pinnedFrom(bridgeMAC string) string {
	if bridgeMAC == "" {
		return ""
	}
	return "ether src " + bridgeMAC
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
