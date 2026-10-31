package cbpf

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/bpf"
)

const (
	maxPaths = 64
	maxSteps = 1 << 16
)

// Decompilation is the packet filter expression a program implements. Clauses
// are alternatives, the atoms inside a clause must all hold.
type Decompilation struct {
	Clauses []string
	// Complete is false when parts of the program could not be expressed, for
	// example indirect loads through the X register.
	Complete bool
}

// Expression renders the clauses as a pcap filter expression. Clauses are
// parenthesised because pcap filter syntax gives "and" and "or" the same
// precedence and associates them left to right.
func (d Decompilation) Expression() string {
	if len(d.Clauses) == 0 {
		return "len < 0"
	}
	if len(d.Clauses) == 1 {
		if d.Clauses[0] == "" {
			return "len >= 0"
		}
		return d.Clauses[0]
	}
	clauses := make([]string, len(d.Clauses))
	for i, clause := range d.Clauses {
		if clause == "" {
			clause = "len >= 0"
		}
		clauses[i] = "(" + clause + ")"
	}
	return strings.Join(clauses, " or ")
}

type value interface {
	value()
}

type constValue struct{ n uint32 }

func (constValue) value() {}

type packetValue struct {
	off  int
	size int
}

func (packetValue) value() {}

type indirectValue struct {
	base value
	off  int
	size int
}

func (indirectValue) value() {}

type maskedValue struct {
	of value
	m  uint32
}

func (maskedValue) value() {}

type shiftedValue struct {
	of value
	n  uint
	up bool
}

func (shiftedValue) value() {}

type arithmeticValue struct {
	of value
	n  uint32
	op string
}

func (arithmeticValue) value() {}

type nibbleValue struct{ at packetValue }

func (nibbleValue) value() {}

type opaqueValue struct{ name string }

func (opaqueValue) value() {}

type atom struct {
	op string
	of value
	n  uint32
}

func (a atom) render(complete *bool) string {
	left := renderValue(a.of, complete)
	switch a.op {
	case "=", "!=", ">", ">=", "<", "<=":
		return fmt.Sprintf("%s %s 0x%x", left, a.op, a.n)
	case "&!=":
		return fmt.Sprintf("%s & 0x%x != 0", left, a.n)
	case "&==":
		return fmt.Sprintf("%s & 0x%x = 0", left, a.n)
	default:
		*complete = false
		return "?"
	}
}

func renderValue(v value, complete *bool) string {
	switch v := v.(type) {
	case constValue:
		return fmt.Sprintf("0x%x", v.n)
	case packetValue:
		return fmt.Sprintf("ether[%d:%d]", v.off, v.size)
	case maskedValue:
		return fmt.Sprintf("%s & 0x%x", renderValue(v.of, complete), v.m)
	case shiftedValue:
		if v.up {
			return fmt.Sprintf("%s << %d", renderValue(v.of, complete), v.n)
		}
		return fmt.Sprintf("%s >> %d", renderValue(v.of, complete), v.n)
	case arithmeticValue:
		return fmt.Sprintf("%s %s 0x%x", renderValue(v.of, complete), v.op, v.n)
	case nibbleValue:
		return fmt.Sprintf("(4*(%s & 0xf))", renderValue(v.at, complete))
	case indirectValue:
		*complete = false
		return fmt.Sprintf("ether[%s+%d:%d]", renderValue(v.base, complete), v.off, v.size)
	case opaqueValue:
		*complete = false
		return v.name
	}
	*complete = false
	return "?"
}

// Decompile recovers the filter expression a program implements.
func (p *Program) Decompile() (Decompilation, error) {
	insns, decoded := bpf.Disassemble(p.insns)
	if !decoded {
		return Decompilation{}, fmt.Errorf("program contains instructions that cannot be decoded")
	}

	result := Decompilation{Complete: true}
	seen := map[string]bool{}
	stack := []state{{a: opaqueValue{"A"}, x: opaqueValue{"X"}}}
	steps := 0
	for len(stack) > 0 {
		st := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for {
			steps++
			if steps > maxSteps {
				return Decompilation{}, fmt.Errorf("program is too large to decompile")
			}
			if st.pc < 0 || st.pc >= len(insns) {
				return Decompilation{}, fmt.Errorf("instruction %d is out of range", st.pc)
			}
			switch in := insns[st.pc].(type) {
			case bpf.RetConstant:
				if in.Val == 0 {
					break
				}
				clause, feasible, complete := renderClause(st.atoms)
				if !complete {
					result.Complete = false
				}
				if feasible && !seen[clause] {
					seen[clause] = true
					result.Clauses = append(result.Clauses, clause)
				}
			case bpf.RetA:
				if c, ok := st.a.(constValue); ok && c.n == 0 {
					break
				}
				clause, feasible, complete := renderClause(st.atoms)
				if !complete {
					result.Complete = false
				}
				if feasible && !seen[clause] {
					seen[clause] = true
					result.Clauses = append(result.Clauses, clause)
				}
			case bpf.LoadAbsolute:
				st.a = packetValue{off: int(in.Off), size: in.Size}
				st.pc++
				continue
			case bpf.LoadIndirect:
				st.a = indirectValue{base: st.x, off: int(in.Off), size: in.Size}
				st.pc++
				continue
			case bpf.LoadConstant:
				st.a = constValue{n: in.Val}
				st.pc++
				continue
			case bpf.LoadMemShift:
				st.x = nibbleValue{at: packetValue{off: int(in.Off), size: 1}}
				st.pc++
				continue
			case bpf.LoadScratch:
				st.a = opaqueValue{fmt.Sprintf("M[%d]", in.N)}
				st.pc++
				continue
			case bpf.LoadExtension:
				st.a = opaqueValue{fmt.Sprintf("extension[%d]", in.Num)}
				st.pc++
				continue
			case bpf.StoreScratch:
				st.pc++
				continue
			case bpf.ALUOpConstant:
				st.a = aluConstant(st.a, in.Op, in.Val)
				st.pc++
				continue
			case bpf.ALUOpX:
				st.a = aluX(st.a, st.x, in.Op)
				st.pc++
				continue
			case bpf.NegateA:
				st.a = aluConstant(st.a, bpf.ALUOpSub, 0)
				st.pc++
				continue
			case bpf.TAX:
				st.x = st.a
				st.pc++
				continue
			case bpf.TXA:
				st.a = st.x
				st.pc++
				continue
			case bpf.JumpIfX:
				if len(stack) >= maxPaths {
					return Decompilation{}, fmt.Errorf("program has too many branches to decompile")
				}
				yes, no := branchAtomsX(in.Cond, st.a, st.x)
				stack = append(stack, state{pc: st.pc + 1 + int(in.SkipFalse), a: st.a, x: st.x, atoms: appendAtoms(st.atoms, no)})
				stack = append(stack, state{pc: st.pc + 1 + int(in.SkipTrue), a: st.a, x: st.x, atoms: appendAtoms(st.atoms, yes)})
			case bpf.Jump:
				st.pc += 1 + int(in.Skip)
				continue
			case bpf.JumpIf:
				if len(stack) >= maxPaths {
					return Decompilation{}, fmt.Errorf("program has too many branches to decompile")
				}
				yes, no := branchAtoms(in.Cond, st.a, in.Val)
				stack = append(stack, state{pc: st.pc + 1 + int(in.SkipFalse), a: st.a, x: st.x, atoms: appendAtoms(st.atoms, no)})
				stack = append(stack, state{pc: st.pc + 1 + int(in.SkipTrue), a: st.a, x: st.x, atoms: appendAtoms(st.atoms, yes)})
			default:
				return Decompilation{}, fmt.Errorf("instruction %d (%v) cannot be decompiled", st.pc, insns[st.pc])
			}
			break
		}
	}
	return result, nil
}

type state struct {
	pc    int
	a, x  value
	atoms []atom
}

func appendAtoms(atoms []atom, a *atom) []atom {
	if a == nil {
		return atoms
	}
	out := make([]atom, len(atoms), len(atoms)+1)
	copy(out, atoms)
	return append(out, *a)
}

func branchAtoms(cond bpf.JumpTest, of value, n uint32) (yes, no *atom) {
	switch cond {
	case bpf.JumpEqual:
		return &atom{op: "=", of: of, n: n}, &atom{op: "!=", of: of, n: n}
	case bpf.JumpNotEqual:
		return &atom{op: "!=", of: of, n: n}, &atom{op: "=", of: of, n: n}
	case bpf.JumpGreaterThan:
		return &atom{op: ">", of: of, n: n}, &atom{op: "<=", of: of, n: n}
	case bpf.JumpLessThan:
		return &atom{op: "<", of: of, n: n}, &atom{op: ">=", of: of, n: n}
	case bpf.JumpGreaterOrEqual:
		return &atom{op: ">=", of: of, n: n}, &atom{op: "<", of: of, n: n}
	case bpf.JumpLessOrEqual:
		return &atom{op: "<=", of: of, n: n}, &atom{op: ">", of: of, n: n}
	case bpf.JumpBitsSet:
		return &atom{op: "&!=", of: of, n: n}, &atom{op: "&==", of: of, n: n}
	case bpf.JumpBitsNotSet:
		return &atom{op: "&==", of: of, n: n}, &atom{op: "&!=", of: of, n: n}
	}
	return nil, nil
}

func branchAtomsX(cond bpf.JumpTest, of, x value) (yes, no *atom) {
	constant, ok := x.(constValue)
	if !ok {
		return &atom{op: "&?", of: of}, &atom{op: "&?", of: of}
	}
	return branchAtoms(cond, of, constant.n)
}

func aluConstant(a value, op bpf.ALUOp, n uint32) value {
	if c, ok := a.(constValue); ok {
		switch op {
		case bpf.ALUOpAdd:
			return constValue{n: c.n + n}
		case bpf.ALUOpSub:
			return constValue{n: c.n - n}
		case bpf.ALUOpMul:
			return constValue{n: c.n * n}
		case bpf.ALUOpDiv:
			if n != 0 {
				return constValue{n: c.n / n}
			}
		case bpf.ALUOpMod:
			if n != 0 {
				return constValue{n: c.n % n}
			}
		case bpf.ALUOpOr:
			return constValue{n: c.n | n}
		case bpf.ALUOpAnd:
			return constValue{n: c.n & n}
		case bpf.ALUOpXor:
			return constValue{n: c.n ^ n}
		case bpf.ALUOpShiftLeft:
			return constValue{n: c.n << n}
		case bpf.ALUOpShiftRight:
			return constValue{n: c.n >> n}
		}
	}
	switch op {
	case bpf.ALUOpAnd:
		if m, ok := a.(maskedValue); ok {
			return maskedValue{of: m.of, m: m.m & n}
		}
		return maskedValue{of: a, m: n}
	case bpf.ALUOpAdd:
		return arithmeticValue{of: a, n: n, op: "+"}
	case bpf.ALUOpSub:
		return arithmeticValue{of: a, n: n, op: "-"}
	case bpf.ALUOpOr:
		return arithmeticValue{of: a, n: n, op: "|"}
	case bpf.ALUOpXor:
		return arithmeticValue{of: a, n: n, op: "^"}
	case bpf.ALUOpShiftLeft:
		return shiftedValue{of: a, n: uint(n), up: true}
	case bpf.ALUOpShiftRight:
		return shiftedValue{of: a, n: uint(n)}
	}
	return opaqueValue{fmt.Sprintf("%v(%v)", op, a)}
}

func aluX(a, x value, op bpf.ALUOp) value {
	cn, aok := a.(constValue)
	cx, xok := x.(constValue)
	if aok && xok {
		return aluConstant(cn, op, cx.n)
	}
	return opaqueValue{fmt.Sprintf("%v(A, X)", op)}
}

type clauseItem struct {
	atom   atom
	text   string
	merged bool
}

// renderClause turns the atoms of one accepting path into a filter expression.
// It reports whether the path can be taken at all and whether every atom could
// be expressed.
func renderClause(atoms []atom) (text string, feasible, complete bool) {
	complete = true
	redundant, feasible := redundantAtoms(atoms)
	if !feasible {
		return "", false, true
	}
	items := make([]clauseItem, 0, len(atoms))
	equalities := map[string]uint32{}
	for _, a := range atoms {
		items = append(items, clauseItem{atom: a, text: renderValue(a.of, &complete)})
		if a.op == "=" {
			equalities[items[len(items)-1].text] = a.n
		}
	}
	for _, it := range items {
		if it.atom.op == "!=" {
			if value, ok := equalities[it.text]; ok && value == it.atom.n {
				return "", false, true
			}
		}
	}

	var parts []string
	protocols := map[uint32]bool{}
	friendly := make([]string, len(items))
	for i, it := range items {
		text, proto, ok := friendlyAtom(it.atom, equalities)
		if !ok {
			continue
		}
		friendly[i] = text
		if pkt, ok := it.atom.of.(packetValue); !ok || pkt.off != etherTypeOff {
			protocols[proto] = true
		}
	}
	for i := range items {
		if text, used := mergeMAC(items, i); used != nil {
			parts = append(parts, text)
			for _, j := range used {
				items[j].merged = true
			}
		}
	}
	for i, it := range items {
		if it.merged {
			continue
		}
		if pkt, ok := it.atom.of.(packetValue); ok && it.atom.op == "=" && pkt.off == etherTypeOff && pkt.size == 2 && protocols[it.atom.n] {
			continue
		}
		if redundant[i] {
			continue
		}
		if friendly[i] != "" {
			parts = append(parts, friendly[i])
			continue
		}
		if it.atom.op == "!=" {
			if _, ok := equalities[it.text]; ok {
				continue
			}
		}
		parts = append(parts, it.atom.render(&complete))
	}
	return strings.Join(parts, " and "), true, complete
}

// redundantAtoms reports atoms that are decided by an equality atom on a
// covering field, and whether the clause can be satisfied at all.
func redundantAtoms(atoms []atom) ([]bool, bool) {
	redundant := make([]bool, len(atoms))
	for i, a := range atoms {
		if a.op == "=" {
			continue
		}
		pkt, ok := a.of.(packetValue)
		if !ok {
			continue
		}
		value, found := coveredValue(atoms, pkt)
		if !found {
			continue
		}
		var holds bool
		switch a.op {
		case "!=":
			holds = value != a.n
		case "&!=":
			holds = value&a.n != 0
		case "&==":
			holds = value&a.n == 0
		case ">":
			holds = value > a.n
		case ">=":
			holds = value >= a.n
		case "<":
			holds = value < a.n
		case "<=":
			holds = value <= a.n
		default:
			continue
		}
		if !holds {
			return nil, false
		}
		redundant[i] = true
	}
	return redundant, true
}

// coveredValue reports the value of an equality atom whose field contains pkt.
func coveredValue(atoms []atom, pkt packetValue) (uint32, bool) {
	for _, a := range atoms {
		if a.op != "=" {
			continue
		}
		other, ok := a.of.(packetValue)
		if !ok || other.off > pkt.off || other.off+other.size < pkt.off+pkt.size {
			continue
		}
		shift := 8 * (other.off + other.size - (pkt.off + pkt.size))
		return (a.n >> uint(shift)) & byteMask(pkt.size), true
	}
	return 0, false
}

func byteMask(size int) uint32 {
	if size >= 4 {
		return 0xffffffff
	}
	return 1<<(8*uint(size)) - 1
}

// mergeMAC joins the equality atoms that together cover one MAC address, which
// cBPF compares as a 4 byte and a 2 byte load in either order.
func mergeMAC(items []clauseItem, i int) (string, []int) {
	if items[i].merged || items[i].atom.op != "=" {
		return "", nil
	}
	pkt, ok := items[i].atom.of.(packetValue)
	if !ok || (pkt.off != etherDstOff && pkt.off != etherSrcOff) {
		return "", nil
	}
	base := etherDstOff
	field := "ether dst"
	if pkt.off >= etherSrcOff {
		base = etherSrcOff
		field = "ether src"
	}
	if pkt.off < base || pkt.off+pkt.size > base+6 {
		return "", nil
	}
	mac := make([]byte, 6)
	covered := make([]bool, 6)
	var used []int
	for j, other := range items {
		if other.merged || other.atom.op != "=" {
			continue
		}
		part, ok := other.atom.of.(packetValue)
		if !ok || part.off < base || part.off+part.size > base+6 {
			continue
		}
		offset := part.off - base
		for k := 0; k < part.size; k++ {
			if covered[offset+k] {
				return "", nil
			}
			covered[offset+k] = true
			mac[offset+k] = byte(other.atom.n >> uint(8*(part.size-1-k)))
		}
		used = append(used, j)
	}
	for _, ok := range covered {
		if !ok {
			return "", nil
		}
	}
	if len(used) < 2 {
		return "", nil
	}
	return field + " " + net.HardwareAddr(mac).String(), used
}

var protocolNames = map[uint32]string{
	etherTypeIPv4: "ip",
	etherTypeARP:  "arp",
	etherTypeRARP: "rarp",
	0x86dd:        "ip6",
}

// friendlyAtom renders well known field tests the way pcap filter syntax spells
// them, together with the ethertype the rendering implies.
func friendlyAtom(a atom, equalities map[string]uint32) (string, uint32, bool) {
	if a.op != "=" {
		return "", 0, false
	}
	mask := uint32(0xffffffff)
	var pkt packetValue
	switch of := a.of.(type) {
	case packetValue:
		pkt = of
	case maskedValue:
		base, ok := of.of.(packetValue)
		if !ok {
			return "", 0, false
		}
		pkt = base
		mask = of.m
	default:
		return "", 0, false
	}
	if pkt.size == 2 && pkt.off == etherTypeOff {
		name, ok := protocolNames[a.n]
		if !ok {
			return "", 0, false
		}
		return name, a.n, true
	}
	if pkt.size != 4 {
		return "", 0, false
	}
	direction := "src"
	if pkt.off == ipv4DstOff || pkt.off == arpDstOff {
		direction = "dst"
	}
	switch {
	case hasEthertype(equalities, etherTypeIPv4) && (pkt.off == ipv4SrcOff || pkt.off == ipv4DstOff):
		return addressPredicate("ip", direction, a.n, mask), etherTypeIPv4, true
	case hasEthertype(equalities, etherTypeARP) && (pkt.off == arpSrcOff || pkt.off == arpDstOff):
		return addressPredicate("arp", direction, a.n, mask), etherTypeARP, true
	case hasEthertype(equalities, etherTypeRARP) && (pkt.off == arpSrcOff || pkt.off == arpDstOff):
		return addressPredicate("rarp", direction, a.n, mask), etherTypeRARP, true
	}
	return "", 0, false
}

func addressPredicate(protocol, direction string, value, mask uint32) string {
	if mask == 0xffffffff {
		return protocol + " " + direction + " host " + ipv4String(value)
	}
	bits, ok := prefixBits(mask)
	if !ok {
		return protocol + " " + direction + " host " + ipv4String(value)
	}
	return fmt.Sprintf("%s %s net %s/%d", protocol, direction, ipv4String(value&mask), bits)
}

func prefixBits(mask uint32) (int, bool) {
	bits := 0
	for bits < 32 && mask&(1<<uint(31-bits)) != 0 {
		bits++
	}
	if bits == 0 {
		return 0, false
	}
	if mask != ^uint32(0)<<uint(32-bits) {
		return 0, false
	}
	return bits, true
}

func ipv4String(n uint32) string {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).String()
}

func hasEthertype(equalities map[string]uint32, want uint32) bool {
	return equalities[fmt.Sprintf("ether[%d:2]", etherTypeOff)] == want
}
