package cbpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/bpf"
)

type label int

type fixup struct {
	idx    int
	target label
}

type emitter struct {
	insns  []bpf.Instruction
	fixups []fixup
	marks  map[label]int
	labels label
	err    error
}

func newEmitter() *emitter {
	return &emitter{marks: make(map[label]int)}
}

func (e *emitter) label() label {
	e.labels++
	return e.labels
}

func (e *emitter) mark(l label) {
	e.marks[l] = len(e.insns)
}

func (e *emitter) emit(in ...bpf.Instruction) {
	e.insns = append(e.insns, in...)
}

// jump appends an unconditional forward jump to l, resolved after codegen.
func (e *emitter) jump(l label) {
	e.fixups = append(e.fixups, fixup{idx: len(e.insns), target: l})
	e.emit(bpf.Jump{})
}

// gotoIf jumps to l when j matches and falls through otherwise.
func (e *emitter) gotoIf(j bpf.JumpIf, l label) {
	j.SkipTrue, j.SkipFalse = 0, 1
	e.emit(j)
	e.jump(l)
}

// branchIf jumps to t when j matches and to f otherwise.
func (e *emitter) branchIf(j bpf.JumpIf, t, f label) {
	j.SkipTrue, j.SkipFalse = 0, 1
	e.emit(j)
	e.jump(t)
	e.jump(f)
}

func (e *emitter) failf(format string, args ...any) {
	if e.err == nil {
		e.err = fmt.Errorf(format, args...)
	}
}

func (e *emitter) resolve() error {
	for _, fx := range e.fixups {
		at, ok := e.marks[fx.target]
		if !ok {
			return fmt.Errorf("unresolved label %d", fx.target)
		}
		skip := at - (fx.idx + 1)
		if skip < 0 {
			return fmt.Errorf("backward jump to label %d", fx.target)
		}
		if e.insns[fx.idx] != (bpf.Jump{}) {
			return fmt.Errorf("fixup at %d is not a jump", fx.idx)
		}
		e.insns[fx.idx] = bpf.Jump{Skip: uint32(skip)}
	}
	return e.compact()
}

// compact drops unconditional jumps that fall through to the next instruction
// and re-targets every jump around the removed instructions.
func (e *emitter) compact() error {
	removed := make([]bool, len(e.insns))
	dropped := 0
	for i, in := range e.insns {
		if j, ok := in.(bpf.Jump); ok && j.Skip == 0 {
			removed[i] = true
			dropped++
		}
	}
	if dropped == 0 {
		return nil
	}
	moved := make([]int, len(e.insns)+1)
	kept := 0
	for i := range e.insns {
		moved[i] = kept
		if !removed[i] {
			kept++
		}
	}
	moved[len(e.insns)] = kept
	out := make([]bpf.Instruction, kept)
	for i, in := range e.insns {
		if removed[i] {
			continue
		}
		at := moved[i]
		switch in := in.(type) {
		case bpf.Jump:
			target := moved[i+1+int(in.Skip)]
			out[at] = bpf.Jump{Skip: uint32(target - (at + 1))}
		case bpf.JumpIf:
			if in.SkipTrue > 0 {
				skip := moved[i+1+int(in.SkipTrue)] - (at + 1)
				if skip > 255 {
					return fmt.Errorf("jump of %d instructions does not fit in 8 bits", skip)
				}
				in.SkipTrue = uint8(skip)
			}
			if in.SkipFalse > 0 {
				skip := moved[i+1+int(in.SkipFalse)] - (at + 1)
				if skip > 255 {
					return fmt.Errorf("jump of %d instructions does not fit in 8 bits", skip)
				}
				in.SkipFalse = uint8(skip)
			}
			out[at] = in
		default:
			out[at] = in
		}
	}
	e.insns = out
	return nil
}

const (
	sizeByte = 1
	sizeHalf = 2
	sizeWord = 4
)

func loadWord(off uint32) bpf.LoadAbsolute {
	return bpf.LoadAbsolute{Off: off, Size: sizeWord}
}

func loadHalf(off uint32) bpf.LoadAbsolute {
	return bpf.LoadAbsolute{Off: off, Size: sizeHalf}
}

func loadByte(off uint32) bpf.LoadAbsolute {
	return bpf.LoadAbsolute{Off: off, Size: sizeByte}
}

func aluAnd(mask uint32) bpf.ALUOpConstant {
	return bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask}
}

func jumpEqual(v uint32) bpf.JumpIf {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: v}
}

func jumpBitsSet(v uint32) bpf.JumpIf {
	return bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: v}
}

// compareWords emits a load followed by an equality test against every value,
// jumping to t on a match and to f when the list is exhausted.
func (e *emitter) compareWords(load bpf.Instruction, values []uint32, t, f label) {
	e.emit(load)
	for _, v := range values {
		e.emit(bpf.JumpIf{Cond: bpf.JumpEqual, Val: v, SkipTrue: 0, SkipFalse: 1})
		e.jump(t)
	}
	e.jump(f)
}

// compareMACs emits an equality test against every address, comparing the
// first four and the last two bytes of the frame separately.
func (e *emitter) compareMACs(off uint32, addrs []net.HardwareAddr, t, f label) {
	for _, a := range addrs {
		e.emit(loadWord(off))
		e.emit(bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       binary.BigEndian.Uint32(a[0:4]),
			SkipTrue:  0,
			SkipFalse: 3,
		})
		e.emit(loadHalf(off + 4))
		e.emit(bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       uint32(binary.BigEndian.Uint16(a[4:6])),
			SkipTrue:  0,
			SkipFalse: 1,
		})
		e.jump(t)
	}
	e.jump(f)
}

// compareHosts matches an address in IPv4, ARP and RARP frames.
func (e *emitter) compareHosts(values []uint32, ipOff, arpOff uint32, t, f label) {
	v4, arp, rarp := e.label(), e.label(), e.label()
	e.emit(loadHalf(etherTypeOff))
	e.gotoIf(jumpEqual(etherTypeIPv4), v4)
	e.gotoIf(jumpEqual(etherTypeARP), arp)
	e.gotoIf(jumpEqual(etherTypeRARP), rarp)
	e.jump(f)
	e.mark(v4)
	e.compareWords(loadWord(ipOff), values, t, f)
	e.mark(arp)
	e.compareWords(loadWord(arpOff), values, t, f)
	e.mark(rarp)
	e.compareWords(loadWord(arpOff), values, t, f)
}

// compareNetworks matches a masked address in IPv4, ARP and RARP frames.
func (e *emitter) compareNetworks(value uint32, mask net.IPMask, ipOff, arpOff uint32, t, f label) {
	v4, arp, rarp := e.label(), e.label(), e.label()
	m := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	network := func(off uint32) {
		if m == 0 {
			e.jump(t)
			return
		}
		e.emit(loadWord(off))
		e.emit(aluAnd(m))
		e.emit(bpf.JumpIf{Cond: bpf.JumpEqual, Val: value, SkipTrue: 0, SkipFalse: 1})
		e.jump(t)
		e.jump(f)
	}
	e.emit(loadHalf(etherTypeOff))
	e.gotoIf(jumpEqual(etherTypeIPv4), v4)
	e.gotoIf(jumpEqual(etherTypeARP), arp)
	e.gotoIf(jumpEqual(etherTypeRARP), rarp)
	e.jump(f)
	e.mark(v4)
	network(ipOff)
	e.mark(arp)
	network(arpOff)
	e.mark(rarp)
	network(arpOff)
}
