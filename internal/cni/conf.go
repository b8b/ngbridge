package cni

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/types"

	"github.com/b8b/libjail/ngbridge/internal/guard"
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
type addressInfo = guard.Address

// inExpression is the filter for the frames that arrive from the container.
func (c *Config) inExpression(jailMAC, hostMAC string, addresses []addressInfo, multicast []string) string {
	return guard.Rule{
		JailMAC:           jailMAC,
		BridgeMAC:         hostMAC,
		Addresses:         addresses,
		ForceGateway:      c.IsForceGateway,
		RestrictMulticast: c.IsRestrictMulticast,
		Networks:          multicast,
	}.In()
}

// outExpression is the filter for the frames that go to the container.
func (c *Config) outExpression(jailMAC, hostMAC string, addresses []addressInfo, multicast []string) string {
	return guard.Rule{
		JailMAC:           jailMAC,
		BridgeMAC:         hostMAC,
		Addresses:         addresses,
		ForceGateway:      c.IsForceGateway,
		RestrictMulticast: c.IsRestrictMulticast,
		Networks:          multicast,
	}.Out()
}

// Attachment is one attachment a GC invocation reports as still valid.
type Attachment struct {
	ContainerID string `json:"containerID"`
	IfName      string `json:"ifname"`
}
