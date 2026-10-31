// Package cbpf builds classic BPF programs for FreeBSD's ng_bpf(4) node.
package cbpf

import (
	"net"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeRARP = 0x8035

	ipv4SrcOff   = 26
	ipv4DstOff   = 30
	arpSrcOff    = 28
	arpDstOff    = 38
	etherSrcOff  = 6
	etherDstOff  = 0
	etherTypeOff = 12
)

// Filter is a boolean predicate over ethernet frames.
type Filter struct {
	gen func(*emitter, label, label)
}

func newFilter(gen func(*emitter, label, label)) Filter {
	return Filter{gen: gen}
}

// All matches every frame.
func All() Filter {
	return newFilter(func(e *emitter, t, _ label) { e.jump(t) })
}

// None matches no frame.
func None() Filter {
	return newFilter(func(e *emitter, _, f label) { e.jump(f) })
}

// Not negates a filter.
func Not(f Filter) Filter {
	return newFilter(func(e *emitter, t, fl label) { f.gen(e, fl, t) })
}

// And matches when every filter matches.
func And(fs ...Filter) Filter {
	return newFilter(func(e *emitter, t, fl label) {
		if len(fs) == 0 {
			e.jump(t)
			return
		}
		for i, f := range fs {
			if i == len(fs)-1 {
				f.gen(e, t, fl)
				return
			}
			next := e.label()
			f.gen(e, next, fl)
			e.mark(next)
		}
	})
}

// Or matches when any filter matches.
func Or(fs ...Filter) Filter {
	return newFilter(func(e *emitter, t, fl label) {
		if len(fs) == 0 {
			e.jump(fl)
			return
		}
		for i, f := range fs {
			if i == len(fs)-1 {
				f.gen(e, t, fl)
				return
			}
			next := e.label()
			f.gen(e, t, next)
			e.mark(next)
		}
	})
}

// EtherType matches frames whose ethernet type is typ.
func EtherType(typ uint16) Filter {
	return newFilter(func(e *emitter, t, f label) {
		e.emit(loadHalf(etherTypeOff))
		e.branchIf(jumpEqual(uint32(typ)), t, f)
	})
}

// IPv4 matches IPv4 frames.
func IPv4() Filter {
	return EtherType(etherTypeIPv4)
}

// ARP matches ARP frames.
func ARP() Filter {
	return EtherType(etherTypeARP)
}

// RARP matches RARP frames.
func RARP() Filter {
	return EtherType(etherTypeRARP)
}

// EtherSrc matches frames whose source MAC is one of addrs.
func EtherSrc(addrs ...net.HardwareAddr) Filter {
	return newFilter(func(e *emitter, t, f label) {
		if len(addrs) == 0 {
			e.jump(t)
			return
		}
		for _, a := range addrs {
			if len(a) != 6 {
				e.failf("ether src: %q is not a 6 byte address", a)
				return
			}
		}
		e.compareMACs(etherSrcOff, addrs, t, f)
	})
}

// EtherDst matches frames whose destination MAC is one of addrs.
func EtherDst(addrs ...net.HardwareAddr) Filter {
	return newFilter(func(e *emitter, t, f label) {
		if len(addrs) == 0 {
			e.jump(t)
			return
		}
		for _, a := range addrs {
			if len(a) != 6 {
				e.failf("ether dst: %q is not a 6 byte address", a)
				return
			}
		}
		e.compareMACs(etherDstOff, addrs, t, f)
	})
}

// EtherMulticast matches frames with the ethernet multicast bit set.
func EtherMulticast() Filter {
	return newFilter(func(e *emitter, t, f label) {
		e.emit(loadByte(etherDstOff))
		e.branchIf(jumpBitsSet(1), t, f)
	})
}

// EtherBroadcast matches frames addressed to ff:ff:ff:ff:ff:ff.
func EtherBroadcast() Filter {
	return newFilter(func(e *emitter, t, f label) {
		last := e.label()
		e.emit(loadWord(etherDstOff))
		e.gotoIf(jumpEqual(0xffffffff), last)
		e.jump(f)
		e.mark(last)
		e.emit(loadHalf(etherDstOff + 4))
		e.branchIf(jumpEqual(0xffff), t, f)
	})
}

// IPSrc matches IPv4, ARP and RARP frames whose sender address is one of
// addrs, mirroring libpcap's "src host".
func IPSrc(addrs ...net.IP) Filter {
	return hostFilter("src host", addrs, ipv4SrcOff, arpSrcOff)
}

// IPDst matches IPv4, ARP and RARP frames whose target address is one of
// addrs, mirroring libpcap's "dst host".
func IPDst(addrs ...net.IP) Filter {
	return hostFilter("dst host", addrs, ipv4DstOff, arpDstOff)
}

// IPv4Src matches IPv4 frames whose source address is one of addrs.
func IPv4Src(addrs ...net.IP) Filter {
	return ipv4AddrFilter("src", addrs, ipv4SrcOff)
}

// IPv4Dst matches IPv4 frames whose destination address is one of addrs.
func IPv4Dst(addrs ...net.IP) Filter {
	return ipv4AddrFilter("dst", addrs, ipv4DstOff)
}

// IPv4Multicast matches IPv4 packets with a multicast destination.
func IPv4Multicast() Filter {
	return newFilter(func(e *emitter, t, f label) {
		v4 := e.label()
		e.emit(loadHalf(etherTypeOff))
		e.gotoIf(jumpEqual(etherTypeIPv4), v4)
		e.jump(f)
		e.mark(v4)
		e.emit(loadWord(ipv4DstOff))
		e.emit(aluAnd(0xf0000000))
		e.branchIf(jumpEqual(0xe0000000), t, f)
	})
}

// IPv4SrcNet matches IPv4, ARP and RARP frames whose sender address is in n,
// mirroring libpcap's "src net".
func IPv4SrcNet(n *net.IPNet) Filter {
	return networkFilter("src net", n, ipv4SrcOff, arpSrcOff)
}

// IPv4DstNet matches IPv4, ARP and RARP frames whose target address is in n,
// mirroring libpcap's "dst net".
func IPv4DstNet(n *net.IPNet) Filter {
	return networkFilter("dst net", n, ipv4DstOff, arpDstOff)
}

func networkFilter(name string, n *net.IPNet, ipOff, arpOff uint32) Filter {
	return newFilter(func(e *emitter, t, f label) {
		ip := n.IP.To4()
		if ip == nil {
			e.failf("%s: %v is not an IPv4 network", name, n)
			return
		}
		mask := n.Mask
		if len(mask) == net.IPv6len {
			mask = mask[12:]
		}
		if len(mask) != net.IPv4len {
			e.failf("%s: %v has a non IPv4 mask", name, n)
			return
		}
		value := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		value &= uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
		e.compareNetworks(value, mask, ipOff, arpOff, t, f)
	})
}

func hostFilter(name string, addrs []net.IP, ipOff, arpOff uint32) Filter {
	return newFilter(func(e *emitter, t, f label) {
		values, ok := ipv4Values(name, e, addrs)
		if !ok {
			return
		}
		if len(values) == 0 {
			e.jump(t)
			return
		}
		e.compareHosts(values, ipOff, arpOff, t, f)
	})
}

func ipv4AddrFilter(name string, addrs []net.IP, off uint32) Filter {
	return newFilter(func(e *emitter, t, f label) {
		values, ok := ipv4Values(name+" host", e, addrs)
		if !ok {
			return
		}
		if len(values) == 0 {
			e.jump(t)
			return
		}
		v4 := e.label()
		e.emit(loadHalf(etherTypeOff))
		e.gotoIf(jumpEqual(etherTypeIPv4), v4)
		e.jump(f)
		e.mark(v4)
		e.compareWords(loadWord(off), values, t, f)
	})
}

func ipv4Values(name string, e *emitter, addrs []net.IP) ([]uint32, bool) {
	values := make([]uint32, 0, len(addrs))
	seen := make(map[uint32]bool, len(addrs))
	for _, a := range addrs {
		v4 := a.To4()
		if v4 == nil {
			e.failf("%s: %v is not an IPv4 address", name, a)
			return nil, false
		}
		v := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
		if seen[v] {
			continue
		}
		seen[v] = true
		values = append(values, v)
	}
	return values, true
}
