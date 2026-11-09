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
	// and the container id, or to take the one the runtime passes in CNI_ARGS.
	MAC string `json:"mac"`
	// Vlan is the VLAN the containers would be put on, which this plugin does
	// not implement: a configuration that asks for one is rejected instead of
	// silently putting the containers on the untagged bridge.
	Vlan int `json:"vlan"`
	// IsGateway puts the gateway address of the IPAM result on the bridge
	// interface, so that a container default route has something to resolve. It
	// is false by default and podman leaves it false for internal networks,
	// which then carry no address on the bridge at all.
	IsGateway bool `json:"isGateway"`
	// IsDefaultGW makes the network the default gateway of its containers: it
	// implies IsGateway, and a default route through the gateway is added when
	// the IPAM result names none. Without a gateway in the result it does
	// nothing, since the route would point nowhere.
	IsDefaultGW bool `json:"isDefaultGateway"`
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

// Validate reports what the configuration is missing or what it asks for that
// this plugin does not implement.
func (c *Config) Validate() error {
	if c.NetConf.Name == "" {
		return fmt.Errorf("the network configuration has no name")
	}
	if c.Bridge == "" {
		return fmt.Errorf("the network configuration of %q has no bridge", c.NetConf.Name)
	}
	if c.Vlan != 0 {
		return fmt.Errorf("the network configuration of %q asks for vlan %d, which is not implemented",
			c.NetConf.Name, c.Vlan)
	}
	// A plugin declares the capabilities the runtime may pass arguments for. One
	// that is declared and ignored changes where the addresses come from without
	// saying so, which is why it is refused instead of being accepted quietly.
	if c.Capabilities["ips"] {
		return fmt.Errorf("the network configuration of %q declares the ips capability, which is not implemented: a container gets one address per network",
			c.NetConf.Name)
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
