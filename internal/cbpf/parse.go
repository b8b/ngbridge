package cbpf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Parse compiles a filter expression into a Filter.
//
// The syntax is the subset of pcap-filter(7) that this compiler can express:
//
//	proto   := "ip" | "arp" | "rarp"
//	dir     := "src" | "dst"
//	term    := ["ether"] [dir] ["host"] address
//	         | [proto] [dir] [host] address
//	         | [proto] [dir] "net" network
//	         | [proto] "broadcast" | [proto] "multicast"
//	         | proto
//	expr    := term | "not" expr | "(" expr ")" | expr ("and"|"or") expr
//
// Two length predicates are understood as well, because they are what filter
// list prints for a program that accepts everything ("len >= 0") and for one
// that accepts nothing ("len < 0"), the kernel default of an ng_bpf hook. Other
// length comparisons would need a length primitive and are refused.
//
// "broadcast" and "multicast" without a protocol are the ethernet ones, as in
// pcap-filter. Everything libpcap can express beyond that, such as "port" or
// "tcp", is rejected with an error naming the keyword.
func Parse(expression string) (Filter, error) {
	tokens := tokenizeExpression(expression)
	if len(tokens) == 0 {
		return Filter{}, fmt.Errorf("empty filter expression")
	}
	p := &parser{tokens: tokens}
	filter, err := p.parseOr()
	if err != nil {
		return Filter{}, err
	}
	if p.more() {
		return Filter{}, fmt.Errorf("unexpected %q in filter expression", strings.Join(p.tokens[p.pos:], " "))
	}
	return filter, nil
}

var expressionOperators = strings.NewReplacer("&&", " and ", "||", " or ", "!", " not ")

func tokenizeExpression(expression string) []string {
	expression = expressionOperators.Replace(expression)
	var tokens []string
	var word strings.Builder
	flush := func() {
		if word.Len() > 0 {
			tokens = append(tokens, word.String())
			word.Reset()
		}
	}
	for i := 0; i < len(expression); i++ {
		r := rune(expression[i])
		switch r {
		case ' ', '\t', '\n', '\r':
			flush()
		case '(', ')':
			flush()
			tokens = append(tokens, string(r))
		case '<', '>', '=':
			flush()
			operator := string(r)
			if i+1 < len(expression) && expression[i+1] == '=' {
				operator += "="
				i++
			}
			tokens = append(tokens, operator)
		default:
			word.WriteRune(r)
		}
	}
	flush()
	return tokens
}

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) more() bool {
	return p.pos < len(p.tokens)
}

func (p *parser) peek() string {
	if !p.more() {
		return ""
	}
	return strings.ToLower(p.tokens[p.pos])
}

func (p *parser) take() string {
	if !p.more() {
		return ""
	}
	token := p.tokens[p.pos]
	p.pos++
	return token
}

func (p *parser) accept(keywords ...string) bool {
	for _, keyword := range keywords {
		if p.peek() == keyword {
			p.pos++
			return true
		}
	}
	return false
}

func (p *parser) rest() string {
	return strings.Join(p.tokens[p.pos:], " ")
}

func (p *parser) parseOr() (Filter, error) {
	left, err := p.parseAnd()
	if err != nil {
		return Filter{}, err
	}
	for p.accept("or") {
		right, err := p.parseAnd()
		if err != nil {
			return Filter{}, err
		}
		left = Or(left, right)
	}
	return left, nil
}

func (p *parser) parseAnd() (Filter, error) {
	left, err := p.parseNot()
	if err != nil {
		return Filter{}, err
	}
	for p.accept("and") {
		right, err := p.parseNot()
		if err != nil {
			return Filter{}, err
		}
		left = And(left, right)
	}
	return left, nil
}

func (p *parser) parseNot() (Filter, error) {
	if p.accept("not") {
		filter, err := p.parseNot()
		if err != nil {
			return Filter{}, err
		}
		return Not(filter), nil
	}
	if p.accept("(") {
		filter, err := p.parseOr()
		if err != nil {
			return Filter{}, err
		}
		if !p.accept(")") {
			return Filter{}, fmt.Errorf("filter expression is missing a closing parenthesis")
		}
		return filter, nil
	}
	if !p.more() {
		return Filter{}, fmt.Errorf("filter expression is incomplete")
	}
	return p.parseTerm()
}

// unsupportedKeywords are the qualifiers of pcap-filter that this compiler has
// no implementation for, so that they produce a clear error.
var unsupportedKeywords = map[string]bool{
	"byte": true, "gateway": true, "greater": true, "ifindex": true,
	"inbound": true, "len": true, "less": true, "link": true, "mpls": true,
	"outbound": true, "port": true, "portrange": true, "pppoed": true,
	"pppoes": true, "proto": true, "protochain": true, "reason": true,
	"rnr": true, "ruleset": true, "srnr": true, "subtype": true, "tcp": true,
	"udp": true, "icmp": true, "icmp6": true, "igmp": true, "sctp": true,
	"vlan": true, "wlan": true,
}

func (p *parser) parseTerm() (Filter, error) {
	if p.peek() == "len" {
		return p.parseLength()
	}
	if isNumber(p.peek()) {
		return p.parseConstant()
	}
	proto := ""
	if p.accept("ether") {
		proto = "ether"
	} else {
		switch p.peek() {
		case "ip", "arp", "rarp":
			proto = p.take()
		}
	}
	dir := ""
	switch p.peek() {
	case "src", "dst":
		dir = p.take()
	}

	if p.peek() == "broadcast" || p.peek() == "multicast" {
		kind := p.take()
		if dir != "" {
			return Filter{}, fmt.Errorf("%s %s is not supported", dir, kind)
		}
		return protoTerm(proto, kind)
	}

	kind := "host"
	switch p.peek() {
	case "host", "net":
		kind = p.take()
	default:
		if unsupportedKeywords[p.peek()] {
			return Filter{}, fmt.Errorf("%q is not supported in filter expressions", p.peek())
		}
		if !p.operandFollows() {
			return protoTerm(proto, "")
		}
	}
	if !p.more() {
		return Filter{}, fmt.Errorf("filter expression is incomplete")
	}
	value := p.take()
	return operandTerm(proto, strings.ToLower(dir), kind, value)
}

// parseLength reads the two length predicates that mean "every frame" and "no
// frame". Anything else would have to compare the packet length, which this
// compiler does not emit, so it is refused instead of being approximated.
func (p *parser) parseLength() (Filter, error) {
	expression := p.rest()
	p.pos++
	operator := p.take()
	value := p.take()
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil || value == "" {
		return Filter{}, fmt.Errorf("length predicate %q needs a number", expression)
	}
	switch {
	case operator == ">=" && number == 0:
		return All(), nil
	case operator == "<" && number == 0:
		return None(), nil
	}
	return Filter{}, fmt.Errorf("length predicate %q is not supported, only \"len >= 0\" and \"len < 0\" are", expression)
}

// parseConstant reads a comparison of two numbers, which is what "0=1" is: a
// term that is always false, and the way tcpdump writes "rejects all packets".
func (p *parser) parseConstant() (Filter, error) {
	expression := p.rest()
	left, err := strconv.ParseUint(p.take(), 10, 32)
	if err != nil {
		return Filter{}, fmt.Errorf("comparison %q needs two numbers", expression)
	}
	operator := p.take()
	right, err := strconv.ParseUint(p.take(), 10, 32)
	if err != nil {
		return Filter{}, fmt.Errorf("comparison %q needs two numbers", expression)
	}
	var matches bool
	switch operator {
	case "=", "==":
		matches = left == right
	case "!=":
		matches = left != right
	case "<":
		matches = left < right
	case "<=":
		matches = left <= right
	case ">":
		matches = left > right
	case ">=":
		matches = left >= right
	default:
		return Filter{}, fmt.Errorf("comparison %q: %q is not an operator", expression, operator)
	}
	if matches {
		return All(), nil
	}
	return None(), nil
}

func isNumber(token string) bool {
	if token == "" {
		return false
	}
	_, err := strconv.ParseUint(token, 10, 32)
	return err == nil
}

// operandFollows reports whether the next token starts an address or network,
// rather than ending or joining the current term.
func (p *parser) operandFollows() bool {
	switch p.peek() {
	case "", "and", "or", "not", ")", "(":
		return false
	}
	return true
}

func protoTerm(proto, kind string) (Filter, error) {
	switch kind {
	case "":
		switch proto {
		case "ip":
			return IPv4(), nil
		case "arp":
			return ARP(), nil
		case "rarp":
			return RARP(), nil
		case "ether":
			return Filter{}, fmt.Errorf(`"ether" needs a qualifier such as "ether host" or "ether multicast"`)
		}
		return Filter{}, fmt.Errorf("filter expression is incomplete")
	case "broadcast":
		if proto == "" || proto == "ether" {
			return EtherBroadcast(), nil
		}
	case "multicast":
		switch proto {
		case "", "ether":
			return EtherMulticast(), nil
		case "ip":
			return IPv4Multicast(), nil
		}
	}
	return Filter{}, fmt.Errorf("%s %s is not supported", proto, kind)
}

func operandTerm(proto, dir, kind, value string) (Filter, error) {
	if proto == "ether" {
		if kind != "host" {
			return Filter{}, fmt.Errorf("ether %s is not supported", kind)
		}
		mac, err := net.ParseMAC(value)
		if err != nil {
			return Filter{}, fmt.Errorf("ether address %q: %w", value, err)
		}
		switch dir {
		case "src":
			return EtherSrc(mac), nil
		case "dst":
			return EtherDst(mac), nil
		}
		return Or(EtherSrc(mac), EtherDst(mac)), nil
	}
	if kind == "net" {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return Filter{}, fmt.Errorf("network %q: %w", value, err)
		}
		var filter Filter
		switch dir {
		case "src":
			filter = IPv4SrcNet(network)
		case "dst":
			filter = IPv4DstNet(network)
		default:
			filter = Or(IPv4SrcNet(network), IPv4DstNet(network))
		}
		return withProtocol(proto, filter)
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return Filter{}, fmt.Errorf("%q is not an IPv4 address", value)
	}
	var filter Filter
	switch dir {
	case "src":
		filter = IPSrc(ip.To4())
	case "dst":
		filter = IPDst(ip.To4())
	default:
		filter = Or(IPSrc(ip.To4()), IPDst(ip.To4()))
	}
	return withProtocol(proto, filter)
}

// withProtocol restricts a host or network filter, which libpcap applies to
// IPv4, ARP and RARP frames alike, to the protocol the expression names.
func withProtocol(proto string, filter Filter) (Filter, error) {
	switch proto {
	case "":
		return filter, nil
	case "ip":
		return And(IPv4(), filter), nil
	case "arp":
		return And(ARP(), filter), nil
	case "rarp":
		return And(RARP(), filter), nil
	}
	return Filter{}, fmt.Errorf("%q is not a filter qualifier", proto)
}
