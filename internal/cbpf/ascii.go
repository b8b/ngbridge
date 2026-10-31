package cbpf

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// HookProgram is the BPF program ng_bpf(4) has installed on one of its hooks.
type HookProgram struct {
	ThisHook   string
	IfMatch    string
	IfNotMatch string
	Program    *Program
}

var (
	hookFieldPattern = regexp.MustCompile(`(thisHook|ifMatch|ifNotMatch)=("(?:[^"\\]|\\.)*")`)
	insnPattern      = regexp.MustCompile(`\{[^}]*\}`)
	fieldPattern     = regexp.MustCompile(`(\w+)=(\S+)`)
	progLenPattern   = regexp.MustCompile(`bpf_prog_len=(\d+)`)
)

// ParseHookProgram parses the ASCII form of struct ng_bpf_hookprog, which is
// what "ngctl msg <node>: getprogram <hook>" replies with. The kernel omits
// structure fields that equal their default value, so every instruction may
// miss jt, jf, k and even code, and code is printed in hex.
func ParseHookProgram(reply string) (HookProgram, error) {
	var hook HookProgram
	for _, match := range hookFieldPattern.FindAllStringSubmatch(reply, -1) {
		value, err := strconv.Unquote(match[2])
		if err != nil {
			return HookProgram{}, fmt.Errorf("parse %s: %w", match[1], err)
		}
		switch match[1] {
		case "thisHook":
			hook.ThisHook = value
		case "ifMatch":
			hook.IfMatch = value
		case "ifNotMatch":
			hook.IfNotMatch = value
		}
	}
	start := strings.Index(reply, "bpf_prog=[")
	if start < 0 {
		return HookProgram{}, fmt.Errorf("no bpf_prog in %q", reply)
	}
	end := strings.LastIndex(reply, "]")
	if end < start {
		return HookProgram{}, fmt.Errorf("unterminated bpf_prog in %q", reply)
	}
	codes := insnPattern.FindAllString(reply[start:end], -1)
	insns := make([]bpf.RawInstruction, 0, len(codes))
	for _, entry := range codes {
		var insn bpf.RawInstruction
		for _, field := range fieldPattern.FindAllStringSubmatch(entry, -1) {
			value, err := strconv.ParseUint(field[2], 0, 32)
			if err != nil {
				return HookProgram{}, fmt.Errorf("parse instruction field %q: %w", field[0], err)
			}
			switch field[1] {
			case "code":
				if value > 0xffff {
					return HookProgram{}, fmt.Errorf("instruction code %q is out of range", field[2])
				}
				insn.Op = uint16(value)
			case "jt":
				if value > 0xff {
					return HookProgram{}, fmt.Errorf("instruction jt %q is out of range", field[2])
				}
				insn.Jt = uint8(value)
			case "jf":
				if value > 0xff {
					return HookProgram{}, fmt.Errorf("instruction jf %q is out of range", field[2])
				}
				insn.Jf = uint8(value)
			case "k":
				insn.K = uint32(value)
			}
		}
		insns = append(insns, insn)
	}
	if len(insns) == 0 {
		return HookProgram{}, fmt.Errorf("no instructions in %q", reply)
	}
	if match := progLenPattern.FindStringSubmatch(reply); match != nil {
		want, err := strconv.Atoi(match[1])
		if err != nil {
			return HookProgram{}, fmt.Errorf("parse bpf_prog_len %q: %w", match[1], err)
		}
		if want != len(insns) {
			return HookProgram{}, fmt.Errorf("bpf_prog_len is %d but %d instructions were read", want, len(insns))
		}
	}
	hook.Program = &Program{insns: insns}
	return hook, nil
}
