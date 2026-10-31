// Package ngctl drives FreeBSD's netgraph through the ngctl(8) command.
package ngctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ErrNoSuchNode reports a path that names a netgraph node that does not exist.
var ErrNoSuchNode = errors.New("no such node")

// ErrAddressInUse reports a node name or a hook that something else already
// holds, which is how netgraph arbitrates between competing callers.
var ErrAddressInUse = errors.New("address already in use")

// taken recognises the errors the kernel and the simulation report for a node
// name or hook that is already in use.
func taken(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"address already in use", "already has hook", "already exists"} {
		if strings.Contains(message, marker) {
			return fmt.Errorf("%w: %v", ErrAddressInUse, err)
		}
	}
	return err
}

// noSuchNode recognises the errors ngctl reports for a missing node: the
// simulation says "no node ...", FreeBSD either names the node or, when the
// path cannot be resolved at all, reports ENOENT as "No such file or
// directory".
func noSuchNode(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"no node", "no such file or directory"} {
		if strings.Contains(message, marker) {
			return fmt.Errorf("%w: %v", ErrNoSuchNode, err)
		}
	}
	return err
}

// Runner executes a command and returns its standard output. RunInput feeds the
// given text to its standard input, which is how ngctl reads a script of
// commands.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	RunInput(ctx context.Context, stdin, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands as child processes.
type ExecRunner struct{}

// Run implements Runner.
func (e ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return e.RunInput(ctx, "", name, args...)
}

// RunInput implements Runner.
func (ExecRunner) RunInput(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

// Node describes a netgraph node as reported by "ngctl show".
type Node struct {
	Name  string
	Type  string
	ID    string
	Hooks int
	Links []Link
}

// Link is one hook of a node and the peer it is connected to.
type Link struct {
	Hook     string
	PeerName string
	PeerType string
	PeerID   string
	PeerHook string
}

// Ngctl sends netgraph commands through the ngctl binary.
type Ngctl struct {
	// Path is the ngctl binary, "ngctl" when empty.
	Path string
	// Runner executes the binary, ExecRunner when nil.
	Runner Runner
}

// New returns an Ngctl that runs the ngctl binary from PATH.
func New() *Ngctl {
	return &Ngctl{Path: "ngctl", Runner: ExecRunner{}}
}

func (n *Ngctl) run(ctx context.Context, args ...string) (string, error) {
	return n.runInput(ctx, "", args...)
}

func (n *Ngctl) runInput(ctx context.Context, stdin string, args ...string) (string, error) {
	path := n.Path
	if path == "" {
		path = "ngctl"
	}
	runner := n.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	out, err := runner.RunInput(ctx, stdin, path, args...)
	return string(out), err
}

// Script runs several ngctl commands in one process, which is the only way to
// refer to a node through a hook of the temporary socket node ngctl creates:
// the hook name is ours alone, while the node list is shared with everything
// else that runs netgraph commands at the same time.
func (n *Ngctl) Script(ctx context.Context, commands ...string) (string, error) {
	if len(commands) == 0 {
		return "", nil
	}
	return n.runInput(ctx, strings.Join(commands, "\n")+"\n", "-f", "-")
}

// MkPeer creates a node of type nodeType connected to hook of the node at
// path, through peerHook on the new node. An empty path means ".". It returns
// the path of the new node, which is empty when path is "." and the node type
// does not name itself, because such a node can only be addressed within the
// same ngctl invocation.
func (n *Ngctl) MkPeer(ctx context.Context, path, nodeType, hook, peerHook string) (string, error) {
	if path == "" {
		path = "."
	}
	if _, err := n.run(ctx, "mkpeer", path, nodeType, hook, peerHook); err != nil {
		return "", taken(err)
	}
	if path == "." {
		return "", nil
	}
	return strings.TrimSuffix(path, ":") + ":" + hook, nil
}

// Name assigns a name to the node at path.
func (n *Ngctl) Name(ctx context.Context, path, name string) error {
	_, err := n.run(ctx, "name", path, name)
	return taken(err)
}

// Connect connects hook of path to peerHook of peerPath. ngctl takes these as
// "connect [path] relpath hook peerhook", where relpath is the node whose
// peerhook is used, so the paths come first.
func (n *Ngctl) Connect(ctx context.Context, path, hook, peerPath, peerHook string) error {
	_, err := n.run(ctx, "connect", path, peerPath, hook, peerHook)
	return taken(err)
}

// RmHook disconnects hook of the node at path from its peer.
func (n *Ngctl) RmHook(ctx context.Context, path, hook string) error {
	_, err := n.run(ctx, "rmhook", path, hook)
	return err
}

// Shutdown shuts down the node at path.
func (n *Ngctl) Shutdown(ctx context.Context, path string) error {
	_, err := n.run(ctx, "shutdown", path)
	return err
}

// Show reports the node at path together with its hooks.
func (n *Ngctl) Show(ctx context.Context, path string) (Node, error) {
	out, err := n.run(ctx, "show", path)
	if err != nil {
		return Node{}, noSuchNode(err)
	}
	return ParseShow(out)
}

// List reports every node in the netgraph system.
func (n *Ngctl) List(ctx context.Context) ([]Node, error) {
	out, err := n.run(ctx, "list")
	if err != nil {
		return nil, err
	}
	return ParseList(out)
}

// IfName reports the interface name of the ethernet node addressed by path.
func (n *Ngctl) IfName(ctx context.Context, path string) (string, error) {
	out, err := n.run(ctx, "msg", path, "getifname")
	if err != nil {
		return "", err
	}
	return ParseIfName(out)
}

// Msg sends a control message to the node at path and returns the reply.
func (n *Ngctl) Msg(ctx context.Context, path, cmd string, args ...string) (string, error) {
	return n.run(ctx, append([]string{"msg", path, cmd}, args...)...)
}

// SetProgram sends NGM_BPF_SET_PROGRAM carrying the ASCII form of the
// ng_bpf_hookprog structure to the node at path.
func (n *Ngctl) SetProgram(ctx context.Context, path, program string) (string, error) {
	return n.Msg(ctx, path, "setprogram", program)
}

// GetProgram sends NGM_BPF_GET_PROGRAM for hook to the ng_bpf node at path and
// returns the ASCII form of the ng_bpf_hookprog reply.
func (n *Ngctl) GetProgram(ctx context.Context, path, hook string) (string, error) {
	if hook == "" {
		return "", fmt.Errorf("getprogram needs a hook name")
	}
	return n.Msg(ctx, path, "getprogram", strconv.Quote(hook))
}

// ParseShow extracts node and hook information from "ngctl show" output, which
// reads
//
//	Name: ngeth0          Type: eiface          ID: 0000000a   Num hooks: 1
//	Local hook      Peer name       Peer type    Peer ID         Peer hook
//	----------      ---------       ---------    -------         ---------
//	link0           ngb0            eiface       0000000b        ether
func ParseShow(out string) (Node, error) {
	node, err := parseNodeLine(out)
	if err != nil {
		return Node{}, err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] == "Local" || strings.HasPrefix(fields[0], "---") {
			continue
		}
		node.Links = append(node.Links, Link{
			Hook:     fields[0],
			PeerName: fields[1],
			PeerType: fields[2],
			PeerID:   fields[3],
			PeerHook: fields[4],
		})
	}
	return node, nil
}

func parseNodeLine(out string) (Node, error) {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "Name:" {
			continue
		}
		node := Node{Name: fields[i+1]}
		for j := i + 1; j+1 < len(fields); j++ {
			switch fields[j] {
			case "Type:":
				node.Type = fields[j+1]
			case "ID:":
				node.ID = fields[j+1]
			case "hooks:":
				hooks, err := strconv.Atoi(fields[j+1])
				if err != nil {
					return Node{}, fmt.Errorf("parse hook count in %q: %w", out, err)
				}
				node.Hooks = hooks
			}
		}
		return node, nil
	}
	return Node{}, fmt.Errorf("no node information in ngctl output %q", out)
}

// ParseList extracts the nodes from "ngctl list" output.
func ParseList(out string) ([]Node, error) {
	nodes := []Node{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Name:") {
			continue
		}
		node, err := parseNodeLine(line)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 && !strings.Contains(out, "total") {
		return nil, fmt.Errorf("no node list in ngctl output %q", out)
	}
	return nodes, nil
}

// ParseIfName extracts the interface name from a getifname reply, which reads
//
//	Rec'd response "getifname" (1) from "[0000000b]:":
//	Args:	"ngeth0"
func ParseIfName(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "Args:")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if name, err := strconv.Unquote(value); err == nil {
			return name, nil
		}
		if value != "" {
			return value, nil
		}
	}
	return "", fmt.Errorf("no interface name in ngctl output %q", out)
}
