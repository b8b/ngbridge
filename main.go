// Command ngbridge creates and filters netgraph bridges with ng_bpf(4).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/b8b/libjail/ngbridge/internal/bridge"
	"github.com/b8b/libjail/ngbridge/internal/cbpf"
	"github.com/b8b/libjail/ngbridge/internal/ngctl"
	"github.com/b8b/libjail/ngbridge/internal/ngsim"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ngbridge: %v\n", err)
		os.Exit(1)
	}
}

const usage = `usage: ngbridge [--ngctl path] [--dry-run] [--json] <command> [flags]

commands:
  bridge list                  list netgraph bridges
  bridge create <name>         create a bridge with its host interface
  bridge destroy <name>        destroy a bridge and its host interface
  port list [bridge]           list bridge ports
  port create <bridge> [port]  create an ethernet port on a bridge
  port destroy <bridge> <port> destroy a port
  filter list [bridge] [port]  list the ng_bpf programs in front of ports
  filter set <bridge> <port>   filter a port, add an ng_bpf node if needed
  filter del <bridge> <port>   remove the filter of a port

flags:
`

// jsonOutput makes the commands that print results emit JSON instead of tables.
var jsonOutput bool

type command func(ctx context.Context, ng *ngctl.Ngctl, args []string) error

func run(args []string) error {
	root := flag.NewFlagSet("ngbridge", flag.ContinueOnError)
	root.SetOutput(os.Stderr)
	ngctlPath := root.String("ngctl", "ngctl", "path of the `ngctl` binary")
	dryRun := root.Bool("dry-run", false, "print the commands instead of running them")
	jsonFlag := root.Bool("json", false, "print the result as JSON")
	root.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		printFlags(os.Stderr, root)
	}
	if err := root.Parse(args); err != nil {
		return err
	}
	jsonOutput = *jsonFlag
	if root.NArg() == 0 {
		root.Usage()
		return fmt.Errorf("no command given")
	}

	ng := ngctl.New()
	ng.Path = *ngctlPath
	if *dryRun {
		sim := ngsim.New()
		seedDryRun(context.Background(), &ngctl.Ngctl{Path: *ngctlPath}, sim, os.Stderr)
		ng.Runner = echoRunner{out: os.Stderr, runner: sim}
	}

	commands := map[string]command{
		"bridge": cmdBridge,
		"port":   cmdPort,
		"filter": cmdFilter,
	}
	cmd, ok := commands[root.Arg(0)]
	if !ok {
		root.Usage()
		return fmt.Errorf("unknown command %q", root.Arg(0))
	}
	return cmd(context.Background(), ng, root.Args()[1:])
}

// seedDryRun loads the live netgraph into the simulation, so that dry runs of
// commands that work on existing nodes see the real topology. When the live
// netgraph cannot be read the simulation starts empty, which is enough for the
// commands that only create.
func seedDryRun(ctx context.Context, source *ngctl.Ngctl, sim *ngsim.Netgraph, out io.Writer) {
	nodes, err := source.List(ctx)
	if err != nil {
		fmt.Fprintf(out, "+ cannot read the live netgraph, simulating from scratch: %v\n", err)
		return
	}
	seeds := make([]ngsim.NodeInfo, 0, len(nodes))
	for _, node := range nodes {
		info := ngsim.NodeInfo{ID: node.ID, Name: node.Name, Type: node.Type}
		path := "[" + node.ID + "]:"
		if node.Name != "" && node.Name != "<unnamed>" {
			path = node.Name + ":"
		}
		if details, err := source.Show(ctx, path); err == nil {
			info.Links = details.Links
		}
		if node.Type == "eiface" {
			if name, err := source.IfName(ctx, path); err == nil {
				info.Ifname = name
			}
		}
		seeds = append(seeds, info)
	}
	sim.Seed(seeds)
}

// echoRunner prints every command before handing it to the simulated
// netgraph, so that --dry-run can be followed without touching the kernel.
type echoRunner struct {
	out    io.Writer
	runner ngctl.Runner
}

func (e echoRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return e.RunInput(ctx, "", name, args...)
}

func (e echoRunner) RunInput(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t\"'") {
			quoted[i] = strconv.Quote(a)
			continue
		}
		quoted[i] = a
	}
	fmt.Fprintf(e.out, "+ %s %s\n", name, strings.Join(quoted, " "))
	if stdin != "" {
		for _, line := range strings.Split(strings.TrimSuffix(stdin, "\n"), "\n") {
			fmt.Fprintf(e.out, "+ %s\n", line)
		}
	}
	return e.runner.RunInput(ctx, stdin, name, args...)
}

func cmdBridge(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ngbridge bridge list|create|destroy")
	}
	switch args[0] {
	case "list":
		return cmdBridgeList(ctx, ng, args[1:])
	case "create":
		return cmdBridgeCreate(ctx, ng, args[1:])
	case "destroy":
		return cmdBridgeDestroy(ctx, ng, args[1:])
	}
	return fmt.Errorf("unknown bridge command %q", args[0])
}

func cmdBridgeList(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("bridge list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	bridges, err := bridge.New(ng).List(ctx)
	if err != nil {
		return err
	}
	return printBridges(bridges)
}

func cmdBridgeCreate(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("bridge create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	iface := fs.String("iface", "", "host interface name, the bridge name by default")
	up := fs.Bool("up", true, "bring the host interface up")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ngbridge bridge create <name> [flags]\n\nflags:")
		printFlags(os.Stderr, fs)
	}
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		fs.Usage()
		return fmt.Errorf("bridge create needs a bridge name")
	}
	created, err := bridge.New(ng).Create(ctx, positional[0], *iface, *up)
	if err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(bridgeRowOf(created))
	}
	return printBridges([]bridge.Bridge{created})
}

func cmdBridgeDestroy(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("bridge destroy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: ngbridge bridge destroy <name>")
	}
	return bridge.New(ng).Destroy(ctx, positional[0])
}

func cmdPort(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ngbridge port list|create|destroy")
	}
	switch args[0] {
	case "list":
		return cmdPortList(ctx, ng, args[1:])
	case "create":
		return cmdPortCreate(ctx, ng, args[1:])
	case "destroy":
		return cmdPortDestroy(ctx, ng, args[1:])
	}
	return fmt.Errorf("unknown port command %q", args[0])
}

func cmdPortList(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("port list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 1 {
		return fmt.Errorf("usage: ngbridge port list [bridge]")
	}
	manager := bridge.New(ng)
	var ports []bridge.Port
	if len(positional) == 0 {
		ports, err = manager.AllPorts(ctx)
	} else {
		ports, err = manager.Ports(ctx, positional[0])
	}
	if err != nil {
		return err
	}
	return printPorts(ports)
}

func cmdPortCreate(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("port create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 || len(positional) > 2 {
		return fmt.Errorf("usage: ngbridge port create <bridge> [port], a port number above 100 being allocated when none is given")
	}
	number := 0
	if len(positional) == 2 {
		number, err = strconv.Atoi(positional[1])
		if err != nil {
			return fmt.Errorf("port %q is not a number", positional[1])
		}
		if number < 1 {
			return fmt.Errorf("port %d is out of range", number)
		}
	}
	created, err := bridge.New(ng).CreatePort(ctx, positional[0], number)
	if err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(portRowOf(created))
	}
	return printPorts([]bridge.Port{created})
}

func cmdPortDestroy(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("port destroy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", false, "succeed when the bridge or port is already gone")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: ngbridge port destroy <bridge> <port> [flags]

Destroys the port and, when it has one, its ng_bpf filter first.

flags:
`)
		printFlags(os.Stderr, fs)
	}
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		fs.Usage()
		return fmt.Errorf("port destroy needs a bridge and a port")
	}
	return ignoreMissing(bridge.New(ng).DestroyPort(ctx, positional[0], positional[1]), *force)
}

// ignoreMissing drops the error of a destroy when everything it removes is
// already gone, which is what a second DEL of the same port looks like.
func ignoreMissing(err error, force bool) error {
	if force && errors.Is(err, bridge.ErrNotFound) {
		return nil
	}
	return err
}

func cmdFilter(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ngbridge filter list [bridge] [port] | filter set <bridge> <port> --in filter --out filter | filter del <bridge> <port>")
	}
	switch args[0] {
	case "list":
		return cmdFilterList(ctx, ng, args[1:])
	case "set":
		return cmdFilterSet(ctx, ng, args[1:])
	case "del", "delete":
		return cmdFilterDel(ctx, ng, args[1:])
	}
	return fmt.Errorf("unknown filter command %q", args[0])
}

func cmdFilterList(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("filter list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 2 {
		return fmt.Errorf("usage: ngbridge filter list [bridge] [port]")
	}
	bridgeName, port := "", ""
	if len(positional) > 0 {
		bridgeName = positional[0]
	}
	if len(positional) > 1 {
		port = positional[1]
	}
	filters, err := bridge.New(ng).Filters(ctx, bridgeName, port)
	if err != nil {
		return err
	}
	return printFilters(filters)
}

type filterRow struct {
	Bridge     string `json:"bridge"`
	Port       string `json:"port"`
	Filter     string `json:"filter"`
	FilterID   string `json:"filter_id"`
	Hook       string `json:"hook"`
	Peer       string `json:"peer"`
	PeerID     string `json:"peer_id"`
	IfMatch    string `json:"ifmatch"`
	IfNotMatch string `json:"ifnotmatch"`
	Insns      int    `json:"insns"`
	Expression string `json:"expression"`
}

func cmdFilterSet(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("filter set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "filter for the frames that arrive from the `port`")
	out := fs.String("out", "", "filter for the frames that go out to the `port`")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: ngbridge filter set <bridge> <port> [flags]

flags:`)
		printFlags(os.Stderr, fs)
		fmt.Fprint(os.Stderr, `
A filter is a pcap-filter(7) expression such as "ip dst host 10.88.0.23" or
"ether broadcast or not ether multicast"; "len >= 0" passes every frame. A
direction without a program accepts every frame as well. Frames that neither
program accepts are handed to the debug hook of the filter node.

A port needs an ethernet node (eiface) or an existing ng_bpf node; anything
else is refused, because netgraph cannot move a connection and only eiface
survives a node without hooks.
`)
	}
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		fs.Usage()
		return fmt.Errorf("filter set needs a bridge and a port")
	}
	inFilter, err := parseFilter(*in)
	if err != nil {
		return fmt.Errorf("--in: %w", err)
	}
	outFilter, err := parseFilter(*out)
	if err != nil {
		return fmt.Errorf("--out: %w", err)
	}
	manager := bridge.New(ng)
	if _, err := manager.SetFilter(ctx, positional[0], positional[1], inFilter, outFilter); err != nil {
		return err
	}
	filters, err := manager.Filters(ctx, positional[0], positional[1])
	if err != nil {
		return err
	}
	return printFilters(filters)
}

func cmdFilterDel(ctx context.Context, ng *ngctl.Ngctl, args []string) error {
	fs := flag.NewFlagSet("filter del", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", false, "succeed when the port has no filter")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: ngbridge filter del <bridge> <port> [flags]

Removes the ng_bpf node in front of the port and connects the device to the
bridge again. The filter has to be a port filter with an ethernet device, and
whatever was attached to its debug hook is left without a hook.

flags:
`)
		printFlags(os.Stderr, fs)
	}
	positional, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		fs.Usage()
		return fmt.Errorf("filter del needs a bridge and a port")
	}
	_, err = bridge.New(ng).DeleteFilter(ctx, positional[0], positional[1])
	return ignoreMissing(err, *force)
}

// parseFilter compiles a filter expression, an empty one accepting every
// frame.
func parseFilter(expression string) (cbpf.Filter, error) {
	if strings.TrimSpace(expression) == "" {
		return cbpf.All(), nil
	}
	return cbpf.Parse(expression)
}

func printFilters(filters []bridge.FilterHook) error {
	if jsonOutput {
		rows := make([]filterRow, 0, len(filters))
		for _, hook := range filters {
			rows = append(rows, filterRow{
				Bridge: hook.Bridge, Port: hook.Port,
				Filter: hook.Node, FilterID: hook.NodeID,
				Hook: hook.Hook, Peer: hook.Peer, PeerID: hook.PeerID,
				IfMatch: hook.Program.IfMatch, IfNotMatch: hook.Program.IfNotMatch,
				Insns: hook.Program.Program.Len(), Expression: hook.Expression,
			})
		}
		return printJSON(rows)
	}
	w := newWriter()
	fmt.Fprintln(w, "BRIDGE\tPORT\tFILTER\tFILTER_ID\tHOOK\tPEER\tPEER_ID\tIFMATCH\tIFNOTMATCH\tINSNS\tEXPRESSION")
	for _, hook := range filters {
		expression := hook.Expression
		if expression == "" {
			expression = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			hook.Bridge, hook.Port, dash(hook.Node), dash(hook.NodeID), hook.Hook,
			dash(hook.Peer), dash(hook.PeerID),
			dash(hook.Program.IfMatch), dash(hook.Program.IfNotMatch),
			hook.Program.Program.Len(), expression)
	}
	return w.Flush()
}

type bridgeRow struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Ports     int    `json:"ports"`
	Peer      string `json:"peer"`
	PeerID    string `json:"peer_id"`
	Interface string `json:"interface"`
	Filter    string `json:"filter"`
	FilterID  string `json:"filter_id"`
}

func bridgeRowOf(b bridge.Bridge) bridgeRow {
	return bridgeRow{
		Name: b.Name, ID: b.ID, Ports: b.Ports,
		Peer: b.PeerName, PeerID: b.PeerID,
		Interface: b.Interface, Filter: b.Filter, FilterID: b.FilterID,
	}
}

func printBridges(bridges []bridge.Bridge) error {
	if jsonOutput {
		rows := make([]bridgeRow, 0, len(bridges))
		for _, b := range bridges {
			rows = append(rows, bridgeRowOf(b))
		}
		return printJSON(rows)
	}
	w := newWriter()
	fmt.Fprintln(w, "NAME\tID\tPORTS\tPEER\tPEER_ID\tINTERFACE\tFILTER\tFILTER_ID")
	for _, b := range bridges {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			b.Name, b.ID, b.Ports, dash(b.PeerName), dash(b.PeerID), dash(b.Interface),
			dash(b.Filter), dash(b.FilterID))
	}
	return w.Flush()
}

type portRow struct {
	Bridge    string `json:"bridge"`
	Port      string `json:"port"`
	Peer      string `json:"peer"`
	PeerID    string `json:"peer_id"`
	Interface string `json:"interface"`
	Filter    string `json:"filter"`
	FilterID  string `json:"filter_id"`
}

func portRowOf(p bridge.Port) portRow {
	filter, filterID := "", ""
	if p.Filtered() {
		filter, filterID = p.PeerName, p.PeerID
	}
	return portRow{
		Bridge: p.Bridge, Port: p.Number(),
		Peer: p.Name, PeerID: p.ID, Interface: p.Interface,
		Filter: filter, FilterID: filterID,
	}
}

func printPorts(ports []bridge.Port) error {
	if jsonOutput {
		rows := make([]portRow, 0, len(ports))
		for _, p := range ports {
			rows = append(rows, portRowOf(p))
		}
		return printJSON(rows)
	}
	w := newWriter()
	fmt.Fprintln(w, "BRIDGE\tPORT\tPEER\tPEER_ID\tINTERFACE\tFILTER\tFILTER_ID")
	for _, p := range ports {
		filter, filterID := "-", "-"
		if p.Filtered() {
			filter, filterID = p.PeerName, p.PeerID
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Bridge, p.Number(), dash(p.Name), dash(p.ID), dash(p.Interface), filter, filterID)
	}
	return w.Flush()
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

// printFlags prints a flag set with the double dashes the commands accept.
func printFlags(w io.Writer, fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		label := "--" + f.Name
		def := f.DefValue
		if getter, ok := f.Value.(flag.Getter); ok {
			switch getter.Get().(type) {
			case bool:
			case int:
				label += " int"
			case string:
				label += " string"
				if def != "" {
					def = strconv.Quote(def)
				}
			}
		}
		if def == "" {
			fmt.Fprintf(w, "  %s\n\t%s\n", label, f.Usage)
			return
		}
		fmt.Fprintf(w, "  %s\n\t%s (default %s)\n", label, f.Usage, def)
	})
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// parse accepts flags before as well as after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func newWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}
