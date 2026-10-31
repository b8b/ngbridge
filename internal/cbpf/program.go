package cbpf

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// DefaultSnaplen is the accept value tcpdump -ddd emits for matching frames.
const DefaultSnaplen uint32 = 262144

// HookNameMax is NG_HOOKSIZ, the netgraph hook name size including the
// terminating NUL.
const HookNameMax = 32

// Program is an assembled classic BPF program.
type Program struct {
	insns []bpf.RawInstruction
}

// Compile turns a filter into a program. A zero snaplen selects DefaultSnaplen.
func Compile(f Filter, snaplen uint32) (*Program, error) {
	if snaplen == 0 {
		snaplen = DefaultSnaplen
	}
	e := newEmitter()
	accept, drop := e.label(), e.label()
	f.gen(e, accept, drop)
	if e.err != nil {
		return nil, e.err
	}
	e.mark(accept)
	e.emit(bpf.RetConstant{Val: snaplen})
	e.mark(drop)
	e.emit(bpf.RetConstant{Val: 0})
	if err := e.resolve(); err != nil {
		return nil, err
	}
	raw, err := bpf.Assemble(e.insns)
	if err != nil {
		return nil, fmt.Errorf("assemble: %w", err)
	}
	return &Program{insns: raw}, nil
}

// Len reports the number of instructions.
func (p *Program) Len() int {
	return len(p.insns)
}

// Instructions returns a copy of the program's instructions.
func (p *Program) Instructions() []bpf.RawInstruction {
	return append([]bpf.RawInstruction(nil), p.insns...)
}

// Bytes encodes the instructions as struct bpf_insn in host byte order.
func (p *Program) Bytes() []byte {
	buf := make([]byte, 0, 8*len(p.insns))
	for _, in := range p.insns {
		buf = binary.NativeEndian.AppendUint16(buf, in.Op)
		buf = append(buf, in.Jt, in.Jf)
		buf = binary.NativeEndian.AppendUint32(buf, in.K)
	}
	return buf
}

// Disassembly renders the program one instruction per line.
func (p *Program) Disassembly() (string, error) {
	insns, complete := bpf.Disassemble(p.insns)
	var b strings.Builder
	for i, in := range insns {
		fmt.Fprintf(&b, "%03d %v\n", i, in)
	}
	if !complete {
		b.WriteString("(incomplete disassembly)\n")
	}
	return b.String(), nil
}

// NGctlProgram renders the program as the ASCII form of an
// NGM_BPF_SET_PROGRAM message, which is what "ngctl msg <node>: setprogram"
// expects.
func (p *Program) NGctlProgram(thisHook, ifMatch, ifNotMatch string) (string, error) {
	hooks := []struct{ field, value string }{
		{"thisHook", thisHook},
		{"ifMatch", ifMatch},
		{"ifNotMatch", ifNotMatch},
	}
	for _, h := range hooks {
		if len(h.value) >= HookNameMax {
			return "", fmt.Errorf("%s %q: netgraph hook names are at most %d bytes", h.field, h.value, HookNameMax-1)
		}
		for _, r := range h.value {
			if r <= ' ' || r == '"' || r == '\\' {
				return "", fmt.Errorf("%s %q: invalid character %q", h.field, h.value, r)
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "{ thisHook=%s ifMatch=%s ifNotMatch=%s bpf_prog_len=%d bpf_prog=[ ",
		strconv.Quote(thisHook), strconv.Quote(ifMatch), strconv.Quote(ifNotMatch), len(p.insns))
	for i, in := range p.insns {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "{ code=%d jt=%d jf=%d k=%d }", in.Op, in.Jt, in.Jf, in.K)
	}
	b.WriteString(" ] }")
	return b.String(), nil
}
